import { useState } from 'react'
import { TrendingUp, BarChart3, Shield, MessageSquare, Activity } from 'lucide-react'
import ChatPanel from './components/ChatPanel'
import TradingDashboard from './components/TradingDashboard'
import MarketOverview from './components/MarketOverview'
import RiskMetrics from './components/RiskMetrics'

type Tab = 'chat' | 'dashboard' | 'market' | 'risk'

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('chat')

  const tabs = [
    { id: 'chat' as Tab, label: 'AI Assistant', icon: MessageSquare },
    { id: 'dashboard' as Tab, label: 'Portfolio', icon: BarChart3 },
    { id: 'market' as Tab, label: 'Markets', icon: TrendingUp },
    { id: 'risk' as Tab, label: 'Risk', icon: Shield },
  ]

  return (
    <div className="flex h-screen bg-gray-950">
      {/* Sidebar */}
      <nav className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="p-6 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <Activity className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white">TradeAI</h1>
              <p className="text-xs text-gray-400">Powered by AgentCore</p>
            </div>
          </div>
        </div>

        <div className="flex-1 p-4 space-y-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-blue-600/20 text-blue-400 border border-blue-600/30'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
              }`}
            >
              <tab.icon className="w-5 h-5" />
              {tab.label}
            </button>
          ))}
        </div>

        <div className="p-4 border-t border-gray-800">
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            AgentCore Connected
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1 overflow-hidden">
        {activeTab === 'chat' && <ChatPanel />}
        {activeTab === 'dashboard' && <TradingDashboard />}
        {activeTab === 'market' && <MarketOverview />}
        {activeTab === 'risk' && <RiskMetrics />}
      </main>
    </div>
  )
}
