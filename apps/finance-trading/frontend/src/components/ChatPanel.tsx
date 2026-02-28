import React, { useState, useRef, useEffect } from 'react'
import { Send, Bot, User, Loader2 } from 'lucide-react'
import { useAgentWebSocket, Message } from '../hooks/useAgentWebSocket'

export default function ChatPanel() {
  const [input, setInput] = useState('')
  const { messages, sendMessage, isConnected, isLoading } = useAgentWebSocket()
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim() || isLoading) return
    sendMessage(input.trim())
    setInput('')
  }

  const quickActions = [
    'Show market overview',
    'Get my portfolio positions',
    'Calculate VaR for $500K at 95% confidence',
    'Run stress test against 2008 crisis',
    'Get quote for NVDA',
  ]

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-800 bg-gray-900/50">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">AI Trading Assistant</h2>
            <p className="text-sm text-gray-400">Powered by Strands Agents + Bedrock AgentCore</p>
          </div>
          <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs ${
            isConnected ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'
          }`}>
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
            {isConnected ? 'Connected' : 'Disconnected'}
          </div>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {messages.map((msg) => (
          <MessageBubble key={msg.id} message={msg} />
        ))}
        {isLoading && (
          <div className="flex items-center gap-2 text-gray-400">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="text-sm">Analyzing...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Actions */}
      {messages.length <= 1 && (
        <div className="px-6 pb-2">
          <div className="flex flex-wrap gap-2">
            {quickActions.map((action) => (
              <button
                key={action}
                onClick={() => sendMessage(action)}
                className="px-3 py-1.5 text-xs bg-gray-800 text-gray-300 rounded-full hover:bg-gray-700 transition-colors border border-gray-700"
              >
                {action}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <form onSubmit={handleSubmit} className="p-4 border-t border-gray-800 bg-gray-900/50">
        <div className="flex items-center gap-3">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about markets, portfolio, risk analysis, or trading..."
            className="flex-1 px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={!input.trim() || isLoading}
            className="p-3 bg-blue-600 rounded-xl text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <Send className="w-5 h-5" />
          </button>
        </div>
      </form>
    </div>
  )
}

function MessageBubble({ message }: { message: Message }) {
  const isUser = message.role === 'user'

  return (
    <div className={`flex gap-3 ${isUser ? 'justify-end' : 'justify-start'}`}>
      {!isUser && (
        <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center flex-shrink-0 mt-1">
          <Bot className="w-5 h-5 text-white" />
        </div>
      )}
      <div
        className={`max-w-[75%] px-4 py-3 rounded-2xl text-sm leading-relaxed ${
          isUser
            ? 'bg-blue-600 text-white rounded-br-md'
            : message.role === 'system'
            ? 'bg-red-900/30 text-red-300 border border-red-800'
            : 'bg-gray-800 text-gray-200 rounded-bl-md border border-gray-700'
        }`}
      >
        <div className="whitespace-pre-wrap">{message.content}</div>
        <div className={`text-xs mt-2 ${isUser ? 'text-blue-200' : 'text-gray-500'}`}>
          {message.timestamp.toLocaleTimeString()}
        </div>
      </div>
      {isUser && (
        <div className="w-8 h-8 bg-gray-700 rounded-lg flex items-center justify-center flex-shrink-0 mt-1">
          <User className="w-5 h-5 text-gray-300" />
        </div>
      )}
    </div>
  )
}
