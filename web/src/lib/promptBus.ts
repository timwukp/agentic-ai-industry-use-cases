/** Tiny window-event bus that lets dashboard widgets prefill the chat panel.
 *
 * Dispatch side: `askAgent('…prompt…')` (e.g. AskAgentButton in a dashboard).
 * Listen side: ChatPanel prefills its input (never auto-sends); AppShell
 * reveals the chat pane.
 */

export const AGENT_PROMPT_EVENT = 'agent-prompt'

export function askAgent(prompt: string) {
  window.dispatchEvent(new CustomEvent(AGENT_PROMPT_EVENT, { detail: prompt }))
}

/* -------------------------- answer charts (reverse) ----------------------- */

/** Charts extracted from an answer, travelling ChatPanel → AppShell.
 *
 * The same window-event trick in the other direction, and for the same reason
 * `askAgent` uses it: the two panes are siblings under AppShell with no shared
 * state, and threading a callback down would mean AppShell owning chat state it
 * has no other use for. An empty array means "dismiss" — the panel has one
 * source of truth, so clearing and setting go through one channel.
 */
export const ANSWER_CHARTS_EVENT = 'answer-charts'

export function publishAnswerCharts(specs: unknown[]) {
  window.dispatchEvent(new CustomEvent(ANSWER_CHARTS_EVENT, { detail: specs }))
}
