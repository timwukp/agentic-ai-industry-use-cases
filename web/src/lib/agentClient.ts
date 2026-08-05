import { config } from './config'
import { languageDirective } from './replyLanguage'
import { createToolTrace, type ToolCall } from './toolTrace'

/**
 * Generates an AgentCore runtime session id. The runtime requires session ids
 * of at least 33 characters; a UUID (36 chars) plus a suffix clears that with
 * margin.
 */
export function newSessionId(): string {
  return `${crypto.randomUUID()}-web`
}

interface InvokeOptions {
  /** Cognito sub of the signed-in user, forwarded as actorId. */
  actorId?: string
  /** Harness ARN override (per-industry); defaults to config.harnessArn. */
  harnessArn?: string
  signal?: AbortSignal
  /**
   * Called for each tool call that completed successfully, with the JSON payload
   * the agent received. This is a side channel rather than part of the yielded
   * stream because the generator's values are the assistant's prose, which the
   * chat panel appends verbatim to a bubble; tool payloads must not land there.
   */
  onToolCall?: (call: ToolCall) => void
}

/** Defensive text extraction across the event shapes AgentCore may emit. */
function extractText(event: unknown): string | undefined {
  if (typeof event === 'string') return event
  if (!event || typeof event !== 'object') return undefined
  const e = event as Record<string, unknown>

  const contentBlockDelta = e.contentBlockDelta as
    | { delta?: { text?: unknown } }
    | undefined
  const delta = e.delta as { text?: unknown } | undefined

  const candidate =
    contentBlockDelta?.delta?.text ?? delta?.text ?? e.text ?? undefined
  return typeof candidate === 'string' ? candidate : undefined
}

/** Pulls final text out of a non-streamed JSON body (.result / .output / .message). */
function extractFinalText(body: unknown): string {
  if (typeof body === 'string') return body
  if (!body || typeof body !== 'object') return ''
  const b = body as Record<string, unknown>

  for (const key of ['result', 'output', 'message']) {
    const value = b[key]
    if (typeof value === 'string') return value
    if (value && typeof value === 'object') {
      const inner = value as Record<string, unknown>
      // message-like: { content: [{ text }] } or { content: "..." }
      const content = inner.content ?? (inner.message as Record<string, unknown> | undefined)?.content
      if (typeof content === 'string') return content
      if (Array.isArray(content)) {
        const text = content
          .map((block) =>
            typeof block === 'string'
              ? block
              : typeof (block as { text?: unknown })?.text === 'string'
                ? ((block as { text: string }).text)
                : '',
          )
          .join('')
        if (text) return text
      }
      if (typeof inner.text === 'string') return inner.text
    }
  }
  const direct = extractText(body)
  if (direct) return direct
  return JSON.stringify(body)
}

/**
 * Incremental parser for the AWS binary eventstream framing:
 * [4B total len][4B headers len][4B prelude CRC][headers][payload][4B msg CRC].
 * Headers are skipped (exception events still carry a JSON payload with a
 * "message" field, which the caller surfaces). CRCs are not verified — TLS
 * already guarantees integrity end to end.
 */
async function* parseEventStream(
  stream: ReadableStream<Uint8Array>,
  signal?: AbortSignal,
): AsyncGenerator<unknown> {
  const reader = stream.getReader()
  let buf = new Uint8Array(0)
  const decoder = new TextDecoder()
  try {
    for (;;) {
      if (signal?.aborted) break
      const { done, value } = await reader.read()
      if (done) break
      const merged = new Uint8Array(buf.length + value.length)
      merged.set(buf)
      merged.set(value, buf.length)
      buf = merged

      for (;;) {
        if (buf.length < 12) break
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
        const totalLen = view.getUint32(0)
        if (buf.length < totalLen) break
        const headersLen = view.getUint32(4)
        const payloadStart = 12 + headersLen
        const payloadEnd = totalLen - 4
        const payloadBytes = buf.subarray(payloadStart, payloadEnd)
        buf = buf.subarray(totalLen)
        if (payloadBytes.length === 0) continue
        try {
          yield JSON.parse(decoder.decode(payloadBytes))
        } catch {
          // non-JSON payload — ignore
        }
      }
    }
  } finally {
    reader.releaseLock()
  }
}

/**
 * Invokes the AgentCore Harness and yields assistant text chunks as they
 * stream back (SSE). Falls back to a single yield for non-streamed JSON.
 */
export async function* invokeAgent(
  prompt: string,
  sessionId: string,
  accessToken: string,
  options: InvokeOptions = {},
): AsyncGenerator<string> {
  const url =
    `${config.agentEndpoint}/harnesses/invoke` +
    `?harnessArn=${encodeURIComponent(options.harnessArn ?? config.harnessArn)}` +
    `&qualifier=DEFAULT`

  const response = await fetch(url, {
    method: 'POST',
    signal: options.signal,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': sessionId,
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
    },
    // The language directive rides along with the sent text but is NOT what the
    // UI displays — ChatPanel keeps the user's own words in the bubble. Appended
    // here rather than in the component so every call site gets it.
    body: JSON.stringify({
      messages: [
        { role: 'user', content: [{ text: prompt + languageDirective(prompt) }] },
      ],
      ...(options.actorId ? { actorId: options.actorId } : {}),
    }),
  })

  if (!response.ok) {
    const detail = await response.text().catch(() => '')
    throw new Error(
      `Agent invoke failed (${response.status})${detail ? `: ${detail.slice(0, 300)}` : ''}`,
    )
  }

  const contentType = response.headers.get('content-type') ?? ''

  // Non-streamed fallback: whole-body JSON response.
  if (contentType.includes('application/json')) {
    const body: unknown = await response.json()
    const text = extractFinalText(body)
    if (text) yield text
    return
  }

  if (!response.body) {
    const text = await response.text()
    if (text) yield text
    return
  }

  // AWS binary eventstream (application/vnd.amazon.eventstream) — the format
  // the AgentCore data plane actually returns for InvokeHarness.
  if (contentType.includes('vnd.amazon.eventstream')) {
    // The same events carry the tool payloads. Collected as they pass rather than
    // buffered, so the chart panel can appear while the prose is still streaming.
    const trace = options.onToolCall ? createToolTrace(options.onToolCall) : null
    try {
      for await (const payload of parseEventStream(response.body, options.signal)) {
        trace?.push(payload)
        const isError = (payload as { message?: unknown }).message
        if (isError && typeof isError === 'string' && !extractText(payload)) {
          throw new Error(isError)
        }
        const text = extractText(payload)
        if (text) yield text
      }
    } finally {
      // Releases a block whose stop event never arrived — including when the
      // caller aborts mid-answer, where the tools have usually already returned.
      trace?.flush()
    }
    return
  }

  // SSE / chunked streaming parse.
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  const processLine = (line: string): string | undefined => {
    const trimmed = line.trim()
    if (!trimmed || !trimmed.startsWith('data:')) return undefined
    const payload = trimmed.slice(5).trim()
    if (!payload || payload === '[DONE]') return undefined
    try {
      return extractText(JSON.parse(payload))
    } catch {
      // Not JSON — ignore unparseable lines per protocol tolerance.
      return undefined
    }
  }

  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })

      let newlineIndex: number
      while ((newlineIndex = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newlineIndex)
        buffer = buffer.slice(newlineIndex + 1)
        const text = processLine(line)
        if (text) yield text
      }
    }
    // Flush any trailing line without a final newline.
    buffer += decoder.decode()
    if (buffer) {
      const text = processLine(buffer)
      if (text) yield text
    }
  } finally {
    reader.releaseLock()
  }
}
