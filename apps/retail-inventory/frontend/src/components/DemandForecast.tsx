import React from 'react'
import { Target, TrendingUp, Calendar, BarChart3, ArrowUpRight, ArrowDownRight } from 'lucide-react'
import {
  Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Area, AreaChart,
  Legend,
} from 'recharts'

const forecastData = Array.from({ length: 30 }, (_, i) => {
  const day = i + 1
  const base = 1200 + Math.sin(day / 5) * 200 + (day < 15 ? day * 8 : (30 - day) * 6)
  const forecast = Math.round(base + Math.random() * 50)
  const upper = Math.round(forecast * 1.15)
  const lower = Math.round(forecast * 0.85)
  const actual = i < 7 ? Math.round(forecast + (Math.random() - 0.5) * 150) : null
  return {
    day: `Day ${day}`,
    forecast,
    upper,
    lower,
    actual,
  }
})

const weeklyDemand = [
  { week: 'Wk 1', Electronics: 3200, Apparel: 2800, Grocery: 4100, Home: 1900, Sports: 1400 },
  { week: 'Wk 2', Electronics: 3500, Apparel: 2600, Grocery: 4300, Home: 2100, Sports: 1200 },
  { week: 'Wk 3', Electronics: 3100, Apparel: 3100, Grocery: 3900, Home: 1800, Sports: 1600 },
  { week: 'Wk 4', Electronics: 3800, Apparel: 2900, Grocery: 4500, Home: 2200, Sports: 1500 },
]

const topGrowing = [
  { product: 'Wireless Earbuds Pro', sku: 'SKU-ELEC-001', growth: 34.2, avgDaily: 85 },
  { product: 'Smart LED Bulb Kit', sku: 'SKU-HOME-033', growth: 28.7, avgDaily: 62 },
  { product: 'Organic Protein Bars', sku: 'SKU-GROC-105', growth: 22.1, avgDaily: 145 },
  { product: 'Running Shoes V3', sku: 'SKU-APRL-042', growth: 19.5, avgDaily: 38 },
  { product: 'Portable Charger 20K', sku: 'SKU-ELEC-055', growth: 17.8, avgDaily: 54 },
]

const topDeclining = [
  { product: 'Basic Wired Earphones', sku: 'SKU-ELEC-089', decline: -24.6, avgDaily: 12 },
  { product: 'Cotton Crew Socks 6pk', sku: 'SKU-APRL-112', decline: -18.3, avgDaily: 28 },
  { product: 'Plastic Storage Bins', sku: 'SKU-HOME-094', decline: -15.7, avgDaily: 18 },
  { product: 'Standard Jump Rope', sku: 'SKU-SPRT-076', decline: -12.1, avgDaily: 8 },
  { product: 'Instant Noodle Variety', sku: 'SKU-GROC-201', decline: -9.8, avgDaily: 42 },
]

const seasonalityData = [
  { month: 'Jan', index: 0.82 },
  { month: 'Feb', index: 0.78 },
  { month: 'Mar', index: 0.91 },
  { month: 'Apr', index: 0.95 },
  { month: 'May', index: 1.02 },
  { month: 'Jun', index: 1.08 },
  { month: 'Jul', index: 1.15 },
  { month: 'Aug', index: 1.12 },
  { month: 'Sep', index: 1.05 },
  { month: 'Oct', index: 1.10 },
  { month: 'Nov', index: 1.25 },
  { month: 'Dec', index: 1.42 },
]

const categoryColors: Record<string, string> = {
  Electronics: '#10b981',
  Apparel: '#6366f1',
  Grocery: '#f59e0b',
  Home: '#8b5cf6',
  Sports: '#ec4899',
}

export default function DemandForecast() {
  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Demand Forecast</h2>

      {/* KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        <KpiCard
          title="Forecast Accuracy (MAPE)"
          value="6.2%"
          icon={Target}
          detail="Lower is better, target < 10%"
          positive
        />
        <KpiCard
          title="Demand Growth"
          value="+12.4%"
          icon={TrendingUp}
          detail="30-day rolling vs prior period"
          positive
        />
        <KpiCard
          title="Peak Day"
          value="Day 14"
          icon={Calendar}
          detail="1,682 units forecasted"
        />
        <KpiCard
          title="Seasonal Index"
          value="0.78"
          icon={BarChart3}
          detail="Below avg (Feb seasonal dip)"
        />
      </div>

      {/* 30-Day Forecast with Confidence Bands */}
      <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
        <h3 className="text-sm font-medium text-gray-400 mb-4">30-Day Demand Forecast with Confidence Interval</h3>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={forecastData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
            <XAxis dataKey="day" stroke="#6b7280" fontSize={11} interval={2} />
            <YAxis stroke="#6b7280" fontSize={12} tickFormatter={(v) => `${v}`} />
            <Tooltip
              contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
              labelStyle={{ color: '#9ca3af' }}
              formatter={(value: unknown, name: string) => {
                if (value === null || value === undefined) return ['-', name]
                const numValue = Number(value)
                const labels: Record<string, string> = {
                  upper: 'Upper Bound',
                  lower: 'Lower Bound',
                  forecast: 'Forecast',
                  actual: 'Actual',
                }
                return [`${numValue} units`, labels[name] || name]
              }}
            />
            <Area type="monotone" dataKey="upper" stroke="none" fill="#059669" fillOpacity={0.1} />
            <Area type="monotone" dataKey="lower" stroke="none" fill="#059669" fillOpacity={0.1} />
            <Line type="monotone" dataKey="upper" stroke="#065f46" strokeWidth={1} strokeDasharray="4 4" dot={false} />
            <Line type="monotone" dataKey="lower" stroke="#065f46" strokeWidth={1} strokeDasharray="4 4" dot={false} />
            <Line type="monotone" dataKey="forecast" stroke="#10b981" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="actual" stroke="#f59e0b" strokeWidth={2} dot={{ r: 3, fill: '#f59e0b' }} connectNulls={false} />
          </AreaChart>
        </ResponsiveContainer>
        <div className="flex justify-center gap-6 mt-2 text-xs text-gray-500">
          <span><span className="inline-block w-4 h-0.5 bg-emerald-500 mr-1 align-middle" /> Forecast</span>
          <span><span className="inline-block w-4 h-0.5 bg-amber-500 mr-1 align-middle" /> Actual</span>
          <span><span className="inline-block w-4 h-0.5 bg-emerald-900 mr-1 align-middle" style={{ borderTop: '1px dashed' }} /> Confidence Band</span>
        </div>
      </div>

      {/* Category Demand Trends + Seasonality */}
      <div className="grid grid-cols-2 gap-6">
        {/* Weekly Category Demand */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Category Demand Trends (Weekly)</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={weeklyDemand} margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
              <XAxis dataKey="week" stroke="#6b7280" fontSize={12} />
              <YAxis stroke="#6b7280" fontSize={12} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: unknown, name: string) => [`${Number(value).toLocaleString()} units`, name]}
              />
              <Legend
                formatter={(value: unknown) => <span className="text-xs text-gray-400">{String(value)}</span>}
              />
              <Bar dataKey="Electronics" fill={categoryColors.Electronics} radius={[2, 2, 0, 0]} />
              <Bar dataKey="Apparel" fill={categoryColors.Apparel} radius={[2, 2, 0, 0]} />
              <Bar dataKey="Grocery" fill={categoryColors.Grocery} radius={[2, 2, 0, 0]} />
              <Bar dataKey="Home" fill={categoryColors.Home} radius={[2, 2, 0, 0]} />
              <Bar dataKey="Sports" fill={categoryColors.Sports} radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Seasonality Index */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Seasonal Pattern (12-Month Index)</h3>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={seasonalityData} margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
              <XAxis dataKey="month" stroke="#6b7280" fontSize={12} />
              <YAxis stroke="#6b7280" fontSize={12} domain={[0.6, 1.6]} tickFormatter={(v) => v.toFixed(1)} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: unknown) => [Number(value).toFixed(2), 'Seasonal Index']}
              />
              <defs>
                <linearGradient id="seasonGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <Area type="monotone" dataKey="index" stroke="#10b981" fill="url(#seasonGradient)" strokeWidth={2} dot={{ r: 4, fill: '#10b981' }} />
              {/* Baseline reference line at 1.0 */}
              <Line type="monotone" dataKey={() => 1.0} stroke="#374151" strokeWidth={1} strokeDasharray="6 4" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-6 mt-2 text-xs text-gray-500">
            <span><span className="inline-block w-4 h-0.5 bg-emerald-500 mr-1 align-middle" /> Index</span>
            <span><span className="inline-block w-4 h-0.5 bg-gray-600 mr-1 align-middle" /> Baseline (1.0)</span>
          </div>
        </div>
      </div>

      {/* Top Growing & Declining Products */}
      <div className="grid grid-cols-2 gap-6">
        {/* Growing */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
            <ArrowUpRight className="w-4 h-4 text-green-400" />
            <h3 className="text-sm font-medium text-gray-400">Top Growing Products</h3>
          </div>
          <div className="divide-y divide-gray-800/50">
            {topGrowing.map((item, i) => (
              <div key={item.sku} className="px-6 py-3 flex items-center justify-between hover:bg-gray-800/30">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-600 w-5">{i + 1}.</span>
                  <div>
                    <div className="text-sm text-gray-200">{item.product}</div>
                    <div className="text-xs text-gray-500">{item.sku}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-bold text-green-400">+{item.growth}%</div>
                  <div className="text-xs text-gray-500">{item.avgDaily} units/day</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Declining */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
            <ArrowDownRight className="w-4 h-4 text-red-400" />
            <h3 className="text-sm font-medium text-gray-400">Top Declining Products</h3>
          </div>
          <div className="divide-y divide-gray-800/50">
            {topDeclining.map((item, i) => (
              <div key={item.sku} className="px-6 py-3 flex items-center justify-between hover:bg-gray-800/30">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-600 w-5">{i + 1}.</span>
                  <div>
                    <div className="text-sm text-gray-200">{item.product}</div>
                    <div className="text-xs text-gray-500">{item.sku}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-bold text-red-400">{item.decline}%</div>
                  <div className="text-xs text-gray-500">{item.avgDaily} units/day</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function KpiCard({ title, value, icon: Icon, detail, positive }: {
  title: string; value: string; icon: React.ElementType; detail: string; positive?: boolean
}) {
  return (
    <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className="w-5 h-5 text-gray-500" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className={`text-sm mt-1 ${positive ? 'text-green-400' : 'text-gray-400'}`}>{detail}</div>
    </div>
  )
}
