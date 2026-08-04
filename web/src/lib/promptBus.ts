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
