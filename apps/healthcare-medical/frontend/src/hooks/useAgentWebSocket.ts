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
      content: 'Hello! I\'m your AI Medical Assistant powered by AWS Bedrock AgentCore. I can help you with:\n\n' +
        '- **Medical Records Analysis** - Patient history review, clinical summaries, and document retrieval\n' +
        '- **Drug Interaction Checking** - Verify medication safety, contraindications, and dosage guidance\n' +
        '- **Triage Assessment** - Symptom evaluation, urgency classification, and care pathway recommendations\n' +
        '- **Appointment Scheduling** - Availability lookup, booking management, and follow-up coordination\n' +
        '- **Lab Result Interpretation** - Reference range analysis, trend detection, and clinical significance\n' +
        '- **Care Gap Analysis** - Overdue screenings, vaccination schedules, and preventive care compliance\n\n' +
        'How can I assist you today?',
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
