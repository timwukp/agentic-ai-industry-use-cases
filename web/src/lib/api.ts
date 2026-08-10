import { useCallback, useEffect, useState } from 'react'
import { config } from './config'
import { getAccessToken } from './auth'

/** GETs `${VITE_API_URL}${path}` with the Cognito access token. */
export async function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  const token = await getAccessToken()
  if (!token) throw new Error('Not signed in')

  const response = await fetch(`${config.apiUrl}${path}`, {
    signal,
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!response.ok) {
    const detail = await response.text().catch(() => '')
    throw new Error(
      `GET ${path} failed (${response.status})${detail ? `: ${detail.slice(0, 200)}` : ''}`,
    )
  }
  return (await response.json()) as T
}

/** POSTs JSON to `${VITE_API_URL}${path}` with the Cognito access token. */
export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const token = await getAccessToken()
  if (!token) throw new Error('Not signed in')

  const response = await fetch(`${config.apiUrl}${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    const detail = await response.text().catch(() => '')
    throw new Error(
      `POST ${path} failed (${response.status})${detail ? `: ${detail.slice(0, 200)}` : ''}`,
    )
  }
  return (await response.json()) as T
}

export interface ApiState<T> {
  data: T | null
  loading: boolean
  error: string | null
  reload: () => void
}

/** Fetches a REST resource with loading / error state and manual reload. */
export function useApi<T>(path: string): ApiState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [nonce, setNonce] = useState(0)

  const reload = useCallback(() => setNonce((n) => n + 1), [])

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    apiGet<T>(path, controller.signal)
      .then((result) => setData(result))
      .catch((err: unknown) => {
        if (controller.signal.aborted) return
        setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
  }, [path, nonce])

  return { data, loading, error, reload }
}
