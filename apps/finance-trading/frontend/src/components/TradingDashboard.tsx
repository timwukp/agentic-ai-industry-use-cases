import React from 'react'
import { ArrowUpRight, ArrowDownRight, DollarSign, TrendingUp, BarChart3 } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart as RPieChart, Pie, Cell } from 'recharts'

const portfolioValue = [
  { date: 'Jan', value: 220000 }, { date: 'Feb', value: 235000 },
  { date: 'Mar', value: 228000 }, { date: 'Apr', value: 242000 },
  { date: 'May', value: 255000 }, { date: 'Jun', value: 248000 },
  { date: 'Jul', value: 262000 }, { date: 'Aug', value: 275000 },
  { date: 'Sep', value: 268000 }, { date: 'Oct', value: 282000 },
  { date: 'Nov', value: 290000 }, { date: 'Dec', value: 305000 },
]

const positions = [
  { symbol: 'AAPL', name: 'Apple Inc', qty: 100, avgCost: 185.50, price: 245.50, pnl: 6000, pnlPct: 32.35 },
  { symbol: 'MSFT', name: 'Microsoft', qty: 50, avgCost: 380.20, price: 478.30, pnl: 4905, pnlPct: 25.80 },
  { symbol: 'NVDA', name: 'NVIDIA', qty: 30, avgCost: 490.00, price: 875.40, pnl: 11562, pnlPct: 78.65 },
  { symbol: 'GOOGL', name: 'Alphabet', qty: 75, avgCost: 145.00, price: 192.80, pnl: 3585, pnlPct: 32.97 },
  { symbol: 'AMZN', name: 'Amazon', qty: 40, avgCost: 178.50, price: 228.15, pnl: 1986, pnlPct: 27.82 },
  { symbol: 'JPM', name: 'JPMorgan', qty: 80, avgCost: 195.00, price: 242.70, pnl: 3816, pnlPct: 24.46 },
]

const allocation = [
  { name: 'Technology', value: 42.5, color: '#3b82f6' },
  { name: 'Healthcare', value: 15.3, color: '#10b981' },
  { name: 'Financials', value: 12.8, color: '#f59e0b' },
  { name: 'Consumer', value: 10.2, color: '#8b5cf6' },
  { name: 'Energy', value: 8.5, color: '#ef4444' },
  { name: 'Other', value: 10.7, color: '#6b7280' },
]

export default function TradingDashboard() {
  const totalValue = 305000
  const totalPnl = 31854
  const totalReturn = 11.67

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Portfolio Dashboard</h2>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard title="Portfolio Value" value={`$${(totalValue / 1000).toFixed(0)}K`} icon={DollarSign} change="+2.3%" positive />
        <StatCard title="Total P&L" value={`+$${(totalPnl / 1000).toFixed(1)}K`} icon={TrendingUp} change={`+${totalReturn}%`} positive />
        <StatCard title="Day's Change" value="+$1,250" icon={ArrowUpRight} change="+0.41%" positive />
        <StatCard title="Positions" value="6" icon={BarChart3} change="Active" />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2 bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Portfolio Value (YTD)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={portfolioValue}>
              <XAxis dataKey="date" stroke="#6b7280" fontSize={12} />
              <YAxis stroke="#6b7280" fontSize={12} tickFormatter={(v) => `$${v / 1000}K`} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                labelStyle={{ color: '#9ca3af' }}
                formatter={(value: number) => [`$${value.toLocaleString()}`, 'Value']}
              />
              <Line type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Sector Allocation</h3>
          <ResponsiveContainer width="100%" height={200}>
            <RPieChart>
              <Pie data={allocation} dataKey="value" cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={2}>
                {allocation.map((entry, i) => (<Cell key={i} fill={entry.color} />))}
              </Pie>
              <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }} />
            </RPieChart>
          </ResponsiveContainer>
          <div className="space-y-1 mt-2">
            {allocation.map((a) => (
              <div key={a.name} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full" style={{ background: a.color }} />
                  <span className="text-gray-400">{a.name}</span>
                </div>
                <span className="text-gray-300">{a.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Positions Table */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h3 className="text-sm font-medium text-gray-400">Positions</h3>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 text-left">Symbol</th>
              <th className="px-6 py-3 text-right">Qty</th>
              <th className="px-6 py-3 text-right">Avg Cost</th>
              <th className="px-6 py-3 text-right">Price</th>
              <th className="px-6 py-3 text-right">Market Value</th>
              <th className="px-6 py-3 text-right">P&L</th>
              <th className="px-6 py-3 text-right">Return</th>
            </tr>
          </thead>
          <tbody>
            {positions.map((pos) => (
              <tr key={pos.symbol} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-6 py-3">
                  <div className="font-medium text-white">{pos.symbol}</div>
                  <div className="text-xs text-gray-500">{pos.name}</div>
                </td>
                <td className="px-6 py-3 text-right text-gray-300">{pos.qty}</td>
                <td className="px-6 py-3 text-right text-gray-300">${pos.avgCost.toFixed(2)}</td>
                <td className="px-6 py-3 text-right text-white font-medium">${pos.price.toFixed(2)}</td>
                <td className="px-6 py-3 text-right text-white">${(pos.qty * pos.price).toLocaleString()}</td>
                <td className={`px-6 py-3 text-right font-medium ${pos.pnl >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                  {pos.pnl >= 0 ? '+' : ''}${pos.pnl.toLocaleString()}
                </td>
                <td className="px-6 py-3 text-right">
                  <span className={`inline-flex items-center gap-1 text-sm ${pos.pnlPct >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                    {pos.pnlPct >= 0 ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                    {pos.pnlPct.toFixed(2)}%
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon: Icon, change, positive }: {
  title: string; value: string; icon: React.ElementType; change: string; positive?: boolean
}) {
  return (
    <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className="w-5 h-5 text-gray-500" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className={`text-sm mt-1 ${positive ? 'text-green-400' : 'text-gray-400'}`}>{change}</div>
    </div>
  )
}
