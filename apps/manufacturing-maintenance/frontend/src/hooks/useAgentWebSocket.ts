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
  isLoading: boolean
  error: string | null
}

export function useAgentWebSocket(wsUrl?: string): UseAgentWebSocketReturn {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '0',
      role: 'assistant',
      content: 'Hello! I\'m your AI Predictive Maintenance Assistant powered by AWS Bedrock AgentCore. I can help you with:\n\n' +
        '- **Sensor Data Analysis** - Real-time monitoring of vibration, temperature, pressure, and acoustic data\n' +
        '- **Failure Prediction (RUL)** - Remaining Useful Life estimation and failure probability assessment\n' +
        '- **Vibration & Thermal Analysis** - FFT spectrum analysis, bearing defect detection, and thermal anomaly identification\n' +
        '- **Maintenance Scheduling** - Optimized preventive and predictive maintenance calendar generation\n' +
        '- **Spare Parts Management** - Inventory forecasting, reorder optimization, and parts availability tracking\n' +
        '- **Work Order Generation** - Automated creation and prioritization of maintenance work orders\n\n' +
        'How can I help you today?',
      timestamp: new Date(),
    },
  ])
  const [isConnected, setIsConnected] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  const url = wsUrl || `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`

  useEffect(() => {
    try {
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        setIsConnected(true)
        setError(null)
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

      ws.onclose = () => {
        setIsConnected(false)
      }

      ws.onerror = () => {
        setError('WebSocket connection failed. Using HTTP fallback.')
        setIsConnected(false)
      }

      return () => ws.close()
    } catch {
      setError('Failed to establish WebSocket connection')
      setIsConnected(false)
    }
  }, [url])

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

  return { messages, sendMessage, isConnected, isLoading, error }
}
