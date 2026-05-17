import { useState, useCallback, useRef, useEffect } from 'react'

export interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  isStreaming?: boolean
}

interface UseAgentWebSocketReturn {
  messages: Message[]
  sendMessage: (content: string) => void
  isConnected: boolean
  isReconnecting: boolean
  isLoading: boolean
  error: string | null
  disconnect: () => void
}

const RECONNECT_INITIAL_DELAY = 1000
const RECONNECT_MAX_DELAY = 30000
const RECONNECT_MULTIPLIER = 2
const RECONNECT_MAX_ATTEMPTS = 10

export function useAgentWebSocket(wsUrl?: string): UseAgentWebSocketReturn {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '0',
      role: 'assistant',
      content: 'Hello! I\'m your AI Trading Assistant powered by AWS Bedrock AgentCore. I can help you with:\n\n' +
        '- **Market Analysis** - Real-time quotes, sector performance, market overview\n' +
        '- **Risk Management** - VaR calculations, stress tests, Monte Carlo simulations\n' +
        '- **Portfolio Management** - Positions, P&L, allocation, rebalancing\n' +
        '- **Trade Execution** - Place orders, check status, trade history\n' +
        '- **Research** - Financial news, SEC filings via web browsing\n\n' +
        'How can I help you today?',
      timestamp: new Date(),
    },
  ])
  const [isConnected, setIsConnected] = useState(false)
  const [isReconnecting, setIsReconnecting] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttemptRef = useRef(0)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const userDisconnectedRef = useRef(false)

  const url = wsUrl || `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`

  // Use a ref to break the circular dependency between connect and scheduleReconnect.
  // scheduleReconnect needs to call connect, and connect needs to call scheduleReconnect.
  // By storing scheduleReconnect in a ref, connect always sees the latest version without
  // needing it in its useCallback dependency array.
  const scheduleReconnectRef = useRef<() => void>(() => {})

  const connect = useCallback(() => {
    if (userDisconnectedRef.current) return

    try {
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        setIsConnected(true)
        setIsReconnecting(false)
        setError(null)
        reconnectAttemptRef.current = 0
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          setIsLoading(false)
          setMessages((prev) => {
            const last = prev[prev.length - 1]
            if (last?.isStreaming) {
              return [
                ...prev.slice(0, -1),
                { ...last, content: last.content + (data.content || data.response || ''), isStreaming: false },
              ]
            }
            return [
              ...prev,
              {
                id: Date.now().toString(),
                role: 'assistant',
                content: data.content || data.response || JSON.stringify(data),
                timestamp: new Date(),
              },
            ]
          })
        } catch {
          setMessages((prev) => [
            ...prev,
            { id: Date.now().toString(), role: 'assistant', content: event.data, timestamp: new Date() },
          ])
          setIsLoading(false)
        }
      }

      ws.onclose = (event) => {
        setIsConnected(false)

        // Only reconnect if not a normal close and not user-initiated
        if (event.code !== 1000 && !userDisconnectedRef.current) {
          scheduleReconnectRef.current()
        }
      }

      ws.onerror = () => {
        setError('WebSocket connection failed. Using HTTP fallback.')
        setIsConnected(false)
      }
    } catch {
      setError('Failed to establish WebSocket connection')
      setIsConnected(false)
      if (!userDisconnectedRef.current) {
        scheduleReconnectRef.current()
      }
    }
  }, [url])

  // Keep the ref in sync with the latest reconnection logic
  scheduleReconnectRef.current = () => {
    if (reconnectAttemptRef.current >= RECONNECT_MAX_ATTEMPTS) {
      setIsReconnecting(false)
      setError('Max reconnection attempts reached. Please refresh the page.')
      return
    }

    setIsReconnecting(true)
    const baseDelay = Math.min(
      RECONNECT_INITIAL_DELAY * Math.pow(RECONNECT_MULTIPLIER, reconnectAttemptRef.current),
      RECONNECT_MAX_DELAY
    )
    // Add random jitter (0-50% of base delay) to prevent thundering herd
    const jitter = Math.random() * baseDelay * 0.5
    const delay = baseDelay + jitter
    reconnectAttemptRef.current += 1

    reconnectTimeoutRef.current = setTimeout(() => {
      connect()
    }, delay)
  }

  const disconnect = useCallback(() => {
    userDisconnectedRef.current = true
    setIsReconnecting(false)

    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    if (wsRef.current) {
      wsRef.current.close(1000)
      wsRef.current = null
    }

    setIsConnected(false)
  }, [])

  useEffect(() => {
    userDisconnectedRef.current = false
    connect()

    return () => {
      userDisconnectedRef.current = true
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      if (wsRef.current) {
        wsRef.current.close(1000)
      }
    }
  }, [connect])

  const sendMessage = useCallback(
    async (content: string) => {
      const userMessage: Message = {
        id: Date.now().toString(),
        role: 'user',
        content,
        timestamp: new Date(),
      }
      setMessages((prev) => [...prev, userMessage])
      setIsLoading(true)

      // Try WebSocket first
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ prompt: content }))
        return
      }

      // HTTP fallback
      try {
        const response = await fetch('/api/invocations', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prompt: content }),
        })
        const data = await response.json()
        setMessages((prev) => [
          ...prev,
          {
            id: (Date.now() + 1).toString(),
            role: 'assistant',
            content: data.response || JSON.stringify(data),
            timestamp: new Date(),
          },
        ])
      } catch (err) {
        setMessages((prev) => [
          ...prev,
          {
            id: (Date.now() + 1).toString(),
            role: 'system',
            content: `Error: ${err instanceof Error ? err.message : 'Failed to get response'}`,
            timestamp: new Date(),
          },
        ])
      } finally {
        setIsLoading(false)
      }
    },
    [],
  )

  return { messages, sendMessage, isConnected, isReconnecting, isLoading, error, disconnect }
}
