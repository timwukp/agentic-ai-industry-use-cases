import React from 'react'
import { DollarSign, Clock, BarChart3, TrendingUp, ArrowUp, ArrowDown } from 'lucide-react'
import {
  Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Area, AreaChart, Legend,
  ComposedChart,
} from 'recharts'

const medianPriceTrend = [
  { month: 'Mar 25', median: 485000, volume: 142 },
  { month: 'Apr 25', median: 492000, volume: 158 },
  { month: 'May 25', median: 510000, volume: 175 },
  { month: 'Jun 25', median: 528000, volume: 189 },
  { month: 'Jul 25', median: 535000, volume: 195 },
  { month: 'Aug 25', median: 541000, volume: 188 },
  { month: 'Sep 25', median: 530000, volume: 172 },
  { month: 'Oct 25', median: 525000, volume: 156 },
  { month: 'Nov 25', median: 518000, volume: 134 },
  { month: 'Dec 25', median: 512000, volume: 118 },
  { month: 'Jan 26', median: 520000, volume: 128 },
  { month: 'Feb 26', median: 532000, volume: 145 },
]

const neighborhoodComparison = [
  { metric: 'Schools', downtown: 72, suburban: 88, waterfront: 80, historic: 85 },
  { metric: 'Safety', downtown: 68, suburban: 91, waterfront: 82, historic: 78 },
  { metric: 'Walkability', downtown: 95, suburban: 62, waterfront: 74, historic: 88 },
  { metric: 'Amenities', downtown: 92, suburban: 78, waterfront: 70, historic: 82 },
  { metric: 'Transit', downtown: 96, suburban: 55, waterfront: 65, historic: 80 },
]

const forecastData = [
  { month: 'Mar 26', forecast: 540000, upper: 565000, lower: 515000 },
  { month: 'Apr 26', forecast: 552000, upper: 582000, lower: 522000 },
  { month: 'May 26', forecast: 568000, upper: 604000, lower: 532000 },
  { month: 'Jun 26', forecast: 580000, upper: 622000, lower: 538000 },
  { month: 'Jul 26', forecast: 588000, upper: 636000, lower: 540000 },
  { month: 'Aug 26', forecast: 592000, upper: 648000, lower: 536000 },
]

const neighborhoodColors: Record<string, string> = {
  downtown: '#06b6d4',
  suburban: '#22d3ee',
  waterfront: '#0e7490',
  historic: '#67e8f9',
}

export default function MarketAnalysis() {
  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Market Analysis</h2>

      {/* Market Indicator Cards */}
      <div className="grid grid-cols-4 gap-4">
        <KpiCard
          title="Median Price"
          value="$532K"
          icon={DollarSign}
          detail="+3.5% YoY"
          positive
        />
        <KpiCard
          title="Days on Market"
          value="18"
          icon={Clock}
          detail="-5 days vs last month"
          positive
        />
        <KpiCard
          title="Active Inventory"
          value="1,247"
          icon={BarChart3}
          detail="2.1 months of supply"
        />
        <PriceTrendCard />
      </div>

      {/* 12-Month Median Price Trend with Volume */}
      <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
        <h3 className="text-sm font-medium text-gray-400 mb-4">12-Month Median Price Trend & Sales Volume</h3>
        <ResponsiveContainer width="100%" height={300}>
          <ComposedChart data={medianPriceTrend} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
            <XAxis dataKey="month" stroke="#6b7280" fontSize={11} />
            <YAxis
              yAxisId="price"
              stroke="#6b7280"
              fontSize={12}
              tickFormatter={(v: number) => `$${(v / 1000).toFixed(0)}K`}
              orientation="left"
            />
            <YAxis
              yAxisId="volume"
              stroke="#6b7280"
              fontSize={12}
              orientation="right"
              tickFormatter={(v: number) => `${v}`}
            />
            <Tooltip
              contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
              labelStyle={{ color: '#9ca3af' }}
              formatter={(value: unknown, name: string) => {
                const numValue = Number(value)
                if (name === 'median') return [`$${(numValue / 1000).toFixed(0)}K`, 'Median Price']
                if (name === 'volume') return [`${numValue} sales`, 'Volume']
                return [String(value), name]
              }}
            />
            <Legend
              formatter={(value: unknown) => {
                const labels: Record<string, string> = { median: 'Median Price', volume: 'Sales Volume' }
                return <span className="text-xs text-gray-400">{labels[String(value)] || String(value)}</span>
              }}
            />
            <Bar yAxisId="volume" dataKey="volume" fill="#164e63" radius={[4, 4, 0, 0]} barSize={28} />
            <Line yAxisId="price" type="monotone" dataKey="median" stroke="#06b6d4" strokeWidth={2.5} dot={{ r: 4, fill: '#06b6d4' }} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>

      {/* Neighborhood Comparison + Market Forecast */}
      <div className="grid grid-cols-2 gap-6">
        {/* Neighborhood Comparison Bar Chart */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Neighborhood Comparison Scores</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={neighborhoodComparison} margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
              <XAxis dataKey="metric" stroke="#6b7280" fontSize={11} />
              <YAxis stroke="#6b7280" fontSize={12} domain={[0, 100]} tickFormatter={(v: number) => `${v}`} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: unknown, name: string) => {
                  const labels: Record<string, string> = {
                    downtown: 'Downtown',
                    suburban: 'Suburban',
                    waterfront: 'Waterfront',
                    historic: 'Historic',
                  }
                  return [`${Number(value)}/100`, labels[name] || name]
                }}
              />
              <Legend
                formatter={(value: unknown) => {
                  const labels: Record<string, string> = {
                    downtown: 'Downtown',
                    suburban: 'Suburban',
                    waterfront: 'Waterfront',
                    historic: 'Historic',
                  }
                  return <span className="text-xs text-gray-400">{labels[String(value)] || String(value)}</span>
                }}
              />
              <Bar dataKey="downtown" fill={neighborhoodColors.downtown} radius={[2, 2, 0, 0]} />
              <Bar dataKey="suburban" fill={neighborhoodColors.suburban} radius={[2, 2, 0, 0]} />
              <Bar dataKey="waterfront" fill={neighborhoodColors.waterfront} radius={[2, 2, 0, 0]} />
              <Bar dataKey="historic" fill={neighborhoodColors.historic} radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Market Forecast with Confidence Bands */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">6-Month Price Forecast with Confidence Band</h3>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={forecastData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
              <XAxis dataKey="month" stroke="#6b7280" fontSize={11} />
              <YAxis stroke="#6b7280" fontSize={12} tickFormatter={(v: number) => `$${(v / 1000).toFixed(0)}K`} domain={['dataMin - 20000', 'dataMax + 20000']} />
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
                  }
                  return [`$${(numValue / 1000).toFixed(0)}K`, labels[name] || name]
                }}
              />
              <defs>
                <linearGradient id="forecastGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <Area type="monotone" dataKey="upper" stroke="none" fill="#0891b2" fillOpacity={0.1} />
              <Area type="monotone" dataKey="lower" stroke="none" fill="#0891b2" fillOpacity={0.1} />
              <Line type="monotone" dataKey="upper" stroke="#155e75" strokeWidth={1} strokeDasharray="4 4" dot={false} />
              <Line type="monotone" dataKey="lower" stroke="#155e75" strokeWidth={1} strokeDasharray="4 4" dot={false} />
              <Area type="monotone" dataKey="forecast" stroke="#06b6d4" fill="url(#forecastGradient)" strokeWidth={2.5} dot={{ r: 4, fill: '#06b6d4' }} />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-6 mt-2 text-xs text-gray-500">
            <span><span className="inline-block w-4 h-0.5 bg-cyan-500 mr-1 align-middle" /> Forecast</span>
            <span><span className="inline-block w-4 h-0.5 bg-cyan-900 mr-1 align-middle" style={{ borderTop: '1px dashed' }} /> Confidence Band</span>
          </div>
        </div>
      </div>

      {/* Buyer vs Seller Market Gauge */}
      <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
        <h3 className="text-sm font-medium text-gray-400 mb-4">Market Condition Indicator</h3>
        <div className="flex items-center gap-8">
          {/* Gauge Visual */}
          <div className="flex-1">
            <div className="relative h-8 bg-gray-800 rounded-full overflow-hidden">
              <div className="absolute inset-0 flex">
                <div className="flex-1 bg-gradient-to-r from-blue-600 to-blue-400" />
                <div className="flex-1 bg-gradient-to-r from-yellow-400 to-yellow-500" />
                <div className="flex-1 bg-gradient-to-r from-red-400 to-red-600" />
              </div>
              {/* Needle position at ~72% (seller's market) */}
              <div className="absolute top-0 bottom-0 w-1 bg-white shadow-lg" style={{ left: '72%' }} />
            </div>
            <div className="flex justify-between mt-2 text-xs text-gray-500">
              <span>Buyer's Market</span>
              <span>Balanced</span>
              <span>Seller's Market</span>
            </div>
          </div>

          {/* Market Stats */}
          <div className="w-72 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">List-to-Sale Ratio</span>
              <span className="text-sm font-bold text-cyan-400">98.7%</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Months of Supply</span>
              <span className="text-sm font-bold text-cyan-400">2.1</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Absorption Rate</span>
              <span className="text-sm font-bold text-cyan-400">47.6%</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Market Status</span>
              <span className="inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border bg-red-900/30 text-red-400 border-red-800/50">
                Seller's Market
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function PriceTrendCard() {
  const trendUp = true
  return (
    <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">Price Trend</span>
        <TrendingUp className="w-5 h-5 text-gray-500" />
      </div>
      <div className="flex items-center gap-2">
        <div className="text-2xl font-bold text-white">+3.5%</div>
        {trendUp ? (
          <ArrowUp className="w-5 h-5 text-green-400" />
        ) : (
          <ArrowDown className="w-5 h-5 text-red-400" />
        )}
      </div>
      <div className="text-sm mt-1 text-green-400">Appreciating market</div>
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
