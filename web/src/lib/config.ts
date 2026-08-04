/** Runtime configuration, read from Vite env at build time. */

function env(name: string, fallback = ''): string {
  const value = (import.meta.env as Record<string, string | undefined>)[name]
  return value ?? fallback
}

export const config = {
  region: env('VITE_REGION', 'us-west-2'),
  userPoolId: env('VITE_USER_POOL_ID'),
  userPoolClientId: env('VITE_USER_POOL_CLIENT_ID'),
  /** Dashboard REST API base URL (API Gateway HTTP API), no trailing slash. */
  apiUrl: env('VITE_API_URL').replace(/\/$/, ''),
  /** Agent invoke base URL; may be same-origin, e.g. '/agent'. */
  agentEndpoint: env('VITE_AGENT_ENDPOINT', '/agent').replace(/\/$/, ''),
  /** AgentCore Harness ARN to invoke. */
  harnessArn: env('VITE_HARNESS_ARN'),
} as const

export type AppConfig = typeof config
