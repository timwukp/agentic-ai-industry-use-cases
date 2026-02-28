import { Shield, AlertTriangle, TrendingDown, Zap } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, AreaChart, Area } from 'recharts'

const stressScenarios = [
  { name: '2008 Financial Crisis', loss: -54, value: -162000 },
  { name: 'COVID Crash 2020', loss: -34, value: -102000 },
  { name: 'Dot-com Bubble', loss: -49, value: -147000 },
  { name: 'Black Monday 1987', loss: -22, value: -66000 },
  { name: 'Interest Rate Shock', loss: -20, value: -60000 },
]

const monteCarloData = Array.from({ length: 60 }, (_, i) => {
  const month = i
  const median = 300000 * Math.exp(0.08 / 12 * month)
  return {
    month: `M${month}`,
    p5: median * 0.65,
    p25: median * 0.85,
    median,
    p75: median * 1.15,
    p95: median * 1.45,
  }
})

export default function RiskMetrics() {
  const portfolioValue = 305000
  const var95 = 12500
  const var99 = 18200

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Risk Analytics</h2>

      {/* VaR Cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-900 rounded-xl p-5 border border-yellow-800/30">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-5 h-5 text-yellow-500" />
            <span className="text-sm text-gray-400">VaR (95%)</span>
          </div>
          <div className="text-2xl font-bold text-yellow-500">-${(var95 / 1000).toFixed(1)}K</div>
          <div className="text-sm text-gray-500 mt-1">{((var95 / portfolioValue) * 100).toFixed(2)}% of portfolio</div>
          <p className="text-xs text-gray-600 mt-2">
            95% confidence the daily loss won't exceed this amount
          </p>
        </div>

        <div className="bg-gray-900 rounded-xl p-5 border border-red-800/30">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-5 h-5 text-red-500" />
            <span className="text-sm text-gray-400">VaR (99%)</span>
          </div>
          <div className="text-2xl font-bold text-red-500">-${(var99 / 1000).toFixed(1)}K</div>
          <div className="text-sm text-gray-500 mt-1">{((var99 / portfolioValue) * 100).toFixed(2)}% of portfolio</div>
          <p className="text-xs text-gray-600 mt-2">
            99% confidence the daily loss won't exceed this amount
          </p>
        </div>

        <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
          <div className="flex items-center gap-2 mb-3">
            <Zap className="w-5 h-5 text-blue-500" />
            <span className="text-sm text-gray-400">Portfolio Beta</span>
          </div>
          <div className="text-2xl font-bold text-blue-500">1.24</div>
          <div className="text-sm text-gray-500 mt-1">Above market sensitivity</div>
          <p className="text-xs text-gray-600 mt-2">
            Portfolio moves ~1.24x relative to the S&P 500
          </p>
        </div>
      </div>

      {/* Stress Test + Monte Carlo */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <div className="flex items-center gap-2 mb-4">
            <TrendingDown className="w-5 h-5 text-red-500" />
            <h3 className="text-sm font-medium text-gray-400">Stress Test Scenarios</h3>
          </div>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={stressScenarios} layout="vertical" margin={{ left: 130 }}>
              <XAxis type="number" stroke="#6b7280" fontSize={12} tickFormatter={(v) => `${v}%`} />
              <YAxis type="category" dataKey="name" stroke="#6b7280" fontSize={11} width={130} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: number) => [`${value}% ($${Math.abs(value * portfolioValue / 100 / 1000).toFixed(0)}K)`, 'Loss']}
              />
              <Bar dataKey="loss" radius={[4, 0, 0, 4]}>
                {stressScenarios.map((_, i) => (
                  <Cell key={i} fill={i === 0 ? '#dc2626' : i < 3 ? '#ef4444' : '#f87171'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Monte Carlo Simulation (5yr, 1000 paths)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={monteCarloData.filter((_, i) => i % 3 === 0)}>
              <XAxis dataKey="month" stroke="#6b7280" fontSize={10} />
              <YAxis stroke="#6b7280" fontSize={10} tickFormatter={(v) => `$${(v / 1000).toFixed(0)}K`} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: number) => [`$${(value / 1000).toFixed(0)}K`, '']}
              />
              <Area type="monotone" dataKey="p95" stackId="1" stroke="none" fill="#1e3a8a" fillOpacity={0.3} />
              <Area type="monotone" dataKey="p75" stackId="2" stroke="none" fill="#2563eb" fillOpacity={0.3} />
              <Area type="monotone" dataKey="median" stroke="#3b82f6" strokeWidth={2} fill="none" />
              <Area type="monotone" dataKey="p25" stackId="3" stroke="none" fill="#2563eb" fillOpacity={0.15} />
              <Area type="monotone" dataKey="p5" stackId="4" stroke="none" fill="#1e3a8a" fillOpacity={0.1} />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-6 mt-2 text-xs text-gray-500">
            <span><span className="inline-block w-3 h-1 bg-blue-900 mr-1" />5th-95th percentile</span>
            <span><span className="inline-block w-3 h-1 bg-blue-600 mr-1" />25th-75th percentile</span>
            <span><span className="inline-block w-3 h-1 bg-blue-500 mr-1" />Median</span>
          </div>
        </div>
      </div>

      {/* Risk Summary */}
      <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
        <h3 className="text-sm font-medium text-gray-400 mb-4">Risk Summary & Recommendations</h3>
        <div className="grid grid-cols-2 gap-6">
          <div className="space-y-3">
            <MetricRow label="Sharpe Ratio" value="1.45" status="good" />
            <MetricRow label="Sortino Ratio" value="1.82" status="good" />
            <MetricRow label="Max Drawdown" value="-18.5%" status="warning" />
            <MetricRow label="Annual Volatility" value="21.3%" status="warning" />
            <MetricRow label="Concentration (HHI)" value="0.185" status="good" />
          </div>
          <div className="bg-gray-800/50 rounded-lg p-4 text-sm text-gray-300 space-y-2">
            <p className="font-medium text-white">Recommendations:</p>
            <ul className="space-y-1.5 text-gray-400">
              <li>- Portfolio beta of 1.24 suggests above-market risk. Consider adding defensive positions.</li>
              <li>- Technology sector concentration at 42.5% exceeds recommended 30% limit.</li>
              <li>- Sharpe ratio of 1.45 indicates good risk-adjusted returns.</li>
              <li>- Consider protective puts on concentrated NVDA position (+78.65% gain).</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

function MetricRow({ label, value, status }: { label: string; value: string; status: 'good' | 'warning' | 'danger' }) {
  const colors = { good: 'text-green-400', warning: 'text-yellow-400', danger: 'text-red-400' }
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-gray-800/50">
      <span className="text-gray-400 text-sm">{label}</span>
      <span className={`font-medium ${colors[status]}`}>{value}</span>
    </div>
  )
}
