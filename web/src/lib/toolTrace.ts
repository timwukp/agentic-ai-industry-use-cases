/** Pulls completed tool calls out of the AgentCore invoke stream.
 *
 * The chat panel used to keep only `delta.text` and throw the rest away. But the
 * stream also carries, verbatim, the JSON each gateway tool returned — the same
 * bytes the model then wrote its prose from. That makes it a better source for
 * the chart panel than re-fetching a dashboard REST route would be: a re-fetch
 * can disagree with the answer on screen (different arguments, a later
 * timestamp), while this cannot, because it *is* the answer's input.
 *
 * The correlation is not obvious from the event shapes, so it is worth stating.
 * A tool call arrives as:
 *
 *   {contentBlockIndex: 1, start: {toolUse:   {name, toolUseId}}}   ← name here
 *   {contentBlockIndex: 1, delta: {toolUse:   {input: "..."}}}
 *   {contentBlockIndex: 1}                                          ← block stop
 *   ...
 *   {contentBlockIndex: 1, start: {toolResult:{status, toolUseId}}}
 *   {contentBlockIndex: 1, delta: {toolResult:[{text: "{\"sec"}]}}   ← payload,
 *   {contentBlockIndex: 1, delta: {toolResult:[{text: "tors\":"}]}}  ← chunked
 *   {contentBlockIndex: 1}
 *
 * `delta.toolResult` carries no toolUseId and no name, so the name can only be
 * recovered through `contentBlockIndex` → toolUseId → name. Block indexes are
 * reused across turns (index 0 is a toolUse, then a toolResult, then assistant
 * text), so state has to be cleared on each block stop rather than accumulated.
 *
 * Failed calls are dropped: an errored result's body is a message like
 * "Unknown tool: market___get_market_overview", not data.
 */

/** One successful tool call, with the payload the agent actually received. */
export interface ToolCall {
  /** Fully-qualified gateway name, e.g. "market-data___get_market_overview". */
  name: string
  /** Bare tool name with the gateway target prefix stripped. */
  tool: string
  payload: unknown
}

interface PendingResult {
  toolUseId: string
  status: string
  chunks: string[]
}

/** Everything before the last "___" is the gateway target, not the tool. */
export function bareToolName(name: string): string {
  const at = name.lastIndexOf('___')
  return at === -1 ? name : name.slice(at + 3)
}

/**
 * Incremental collector. `push` each parsed stream event in order, then `flush`
 * once the stream ends to release a final block that never got its stop event.
 */
export function createToolTrace(onCall: (call: ToolCall) => void) {
  /** toolUseId → tool name, learned from the toolUse block. */
  const names = new Map<string, string>()
  /** contentBlockIndex → in-progress tool result. */
  const open = new Map<number, PendingResult>()

  const finish = (index: number) => {
    const pending = open.get(index)
    if (!pending) return
    open.delete(index)
    // An errored result carries a diagnostic string, not data.
    if (pending.status !== 'success') return
    const name = names.get(pending.toolUseId)
    if (!name) return
    let payload: unknown
    try {
      payload = JSON.parse(pending.chunks.join(''))
    } catch {
      // Non-JSON bodies are legitimate — the `skills` tool returns Markdown.
      return
    }
    onCall({ name, tool: bareToolName(name), payload })
  }

  return {
    push(event: unknown) {
      if (!event || typeof event !== 'object') return
      const e = event as Record<string, unknown>
      const index = e.contentBlockIndex
      if (typeof index !== 'number') return

      const start = e.start as Record<string, unknown> | undefined
      const delta = e.delta as Record<string, unknown> | undefined

      if (start) {
        const toolUse = start.toolUse as { name?: unknown; toolUseId?: unknown } | undefined
        if (typeof toolUse?.name === 'string' && typeof toolUse.toolUseId === 'string') {
          names.set(toolUse.toolUseId, toolUse.name)
        }
        const toolResult = start.toolResult as
          | { status?: unknown; toolUseId?: unknown }
          | undefined
        if (typeof toolResult?.toolUseId === 'string') {
          // A new start on this index supersedes anything still open there.
          finish(index)
          open.set(index, {
            toolUseId: toolResult.toolUseId,
            status: typeof toolResult.status === 'string' ? toolResult.status : '',
            chunks: [],
          })
        }
        return
      }

      if (delta) {
        const result = delta.toolResult
        const pending = open.get(index)
        if (Array.isArray(result) && pending) {
          for (const block of result) {
            const text = (block as { text?: unknown } | null)?.text
            if (typeof text === 'string') pending.chunks.push(text)
          }
        }
        return
      }

      // Neither start nor delta on a numbered block: the block-stop event.
      finish(index)
    },

    flush() {
      for (const index of [...open.keys()]) finish(index)
    },
  }
}
