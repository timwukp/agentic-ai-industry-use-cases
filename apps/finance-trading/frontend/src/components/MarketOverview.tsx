import { ArrowUpRight, ArrowDownRight, Globe, Activity } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const indices = [
  { name: 'S&P 500', value: '6,120.35', change: '+0.82%', positive: true },
  { name: 'NASDAQ', value: '19,845.20', change: '+1.15%', positive: true },
  { name: 'DOW', value: '44,250.80', change: '+0.35%', positive: true },
  { name: 'Russell 2000', value: '2,285.40', change: '-0.42%', positive: false },
]

const sectors = [
  { name: 'Technology', change: 1.85 },
  { name: 'Healthcare', change: 0.72 },
  { name: 'Financials', change: -0.34 },
  { name: 'Consumer Disc.', change: 1.12 },
  { name: 'Comm Services', change: 0.45 },
  { name: 'Industrials', change: -0.18 },
  { name: 'Consumer Staples', change: 0.22 },
  { name: 'Energy', change: -1.25 },
  { name: 'Utilities', change: 0.55 },
  { name: 'Real Estate', change: -0.67 },
  { name: 'Materials', change: 0.31 },
]

const movers = [
  { symbol: 'NVDA', name: 'NVIDIA', price: '$875.40', change: '+4.2%', positive: true },
  { symbol: 'TSLA', name: 'Tesla', price: '$248.90', change: '+3.8%', positive: true },
  { symbol: 'META', name: 'Meta', price: '$615.20', change: '+2.1%', positive: true },
  { symbol: 'XOM', name: 'Exxon', price: '$108.70', change: '-2.5%', positive: false },
  { symbol: 'PFE', name: 'Pfizer', price: '$26.30', change: '-1.8%', positive: false },
]

export default function MarketOverview() {
  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">Market Overview</h2>
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <Globe className="w-4 h-4" />
          Market Open
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
        </div>
      </div>

      {/* Indices */}
      <div className="grid grid-cols-4 gap-4">
        {indices.map((idx) => (
          <div key={idx.name} className="bg-gray-900 rounded-xl p-5 border border-gray-800">
            <div className="text-sm text-gray-400 mb-1">{idx.name}</div>
            <div className="text-xl font-bold text-white">{idx.value}</div>
            <div className={`flex items-center gap-1 text-sm mt-1 ${idx.positive ? 'text-green-400' : 'text-red-400'}`}>
              {idx.positive ? <ArrowUpRight className="w-4 h-4" /> : <ArrowDownRight className="w-4 h-4" />}
              {idx.change}
            </div>
          </div>
        ))}
      </div>

      {/* Sector Performance + Top Movers */}
      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2 bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Sector Performance (Daily)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={sectors} layout="vertical" margin={{ left: 100 }}>
              <XAxis type="number" stroke="#6b7280" fontSize={12} tickFormatter={(v) => `${v}%`} />
              <YAxis type="category" dataKey="name" stroke="#6b7280" fontSize={11} width={100} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: number) => [`${value > 0 ? '+' : ''}${value}%`, 'Change']}
              />
              <Bar dataKey="change" radius={[0, 4, 4, 0]}>
                {sectors.map((entry, i) => (
                  <Cell key={i} fill={entry.change >= 0 ? '#10b981' : '#ef4444'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Top Movers</h3>
          <div className="space-y-3">
            {movers.map((m) => (
              <div key={m.symbol} className="flex items-center justify-between py-2 border-b border-gray-800/50 last:border-0">
                <div>
                  <div className="font-medium text-white text-sm">{m.symbol}</div>
                  <div className="text-xs text-gray-500">{m.name}</div>
                </div>
                <div className="text-right">
                  <div className="text-sm text-white">{m.price}</div>
                  <div className={`text-xs ${m.positive ? 'text-green-400' : 'text-red-400'}`}>{m.change}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* VIX + Treasury */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-5 h-5 text-yellow-500" />
            <h3 className="text-sm font-medium text-gray-400">Volatility Index (VIX)</h3>
          </div>
          <div className="text-3xl font-bold text-yellow-500">18.5</div>
          <div className="text-sm text-gray-400 mt-1">Normal range (12-20)</div>
          <div className="mt-4 h-2 bg-gray-800 rounded-full overflow-hidden">
            <div className="h-full bg-gradient-to-r from-green-500 via-yellow-500 to-red-500" style={{ width: '37%' }} />
          </div>
          <div className="flex justify-between text-xs text-gray-500 mt-1">
            <span>Low</span><span>Normal</span><span>Elevated</span><span>High</span>
          </div>
        </div>

        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Treasury Yields</h3>
          <div className="space-y-4">
            {[
              { maturity: '2-Year', yield_: '4.25%', change: '+0.03%' },
              { maturity: '10-Year', yield_: '4.42%', change: '-0.02%' },
              { maturity: '30-Year', yield_: '4.58%', change: '-0.01%' },
            ].map((t) => (
              <div key={t.maturity} className="flex items-center justify-between">
                <span className="text-gray-400">{t.maturity}</span>
                <div className="text-right">
                  <span className="text-white font-medium">{t.yield_}</span>
                  <span className="text-xs text-gray-500 ml-2">{t.change}</span>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 text-xs text-gray-500">
            Yield curve: <span className="text-yellow-400">Normal (positive slope)</span>
          </div>
        </div>
      </div>
    </div>
  )
}
