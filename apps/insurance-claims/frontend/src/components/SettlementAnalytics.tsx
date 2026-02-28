import React from 'react'
import { DollarSign, Clock, TrendingUp, Star } from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell,
  AreaChart, Area,
} from 'recharts'

const monthlySettlements = [
  { month: 'Mar', settled: 82, amount: 1250000 },
  { month: 'Apr', settled: 91, amount: 1380000 },
  { month: 'May', settled: 78, amount: 1120000 },
  { month: 'Jun', settled: 95, amount: 1450000 },
  { month: 'Jul', settled: 88, amount: 1320000 },
  { month: 'Aug', settled: 102, amount: 1580000 },
  { month: 'Sep', settled: 97, amount: 1490000 },
  { month: 'Oct', settled: 110, amount: 1720000 },
  { month: 'Nov', settled: 105, amount: 1650000 },
  { month: 'Dec', settled: 118, amount: 1890000 },
  { month: 'Jan', settled: 112, amount: 1780000 },
  { month: 'Feb', settled: 94, amount: 1520000 },
]

const settlementByType = [
  { type: 'Auto Collision', count: 385, avgAmount: 11200, totalAmount: 4312000, color: '#818cf8' },
  { type: 'Property', count: 142, avgAmount: 28500, totalAmount: 4047000, color: '#6366f1' },
  { type: 'Liability', count: 98, avgAmount: 15800, totalAmount: 1548400, color: '#4f46e5' },
  { type: 'Medical', count: 156, avgAmount: 18900, totalAmount: 2948400, color: '#4338ca' },
  { type: 'Theft', count: 67, avgAmount: 22400, totalAmount: 1500800, color: '#3730a3' },
  { type: 'Fire/Water', count: 45, avgAmount: 42000, totalAmount: 1890000, color: '#312e81' },
]

const amountDistribution = [
  { range: '$0-5K', count: 245, color: '#a5b4fc' },
  { range: '$5-10K', count: 198, color: '#818cf8' },
  { range: '$10-25K', count: 156, color: '#6366f1' },
  { range: '$25-50K', count: 78, color: '#4f46e5' },
  { range: '$50-100K', count: 32, color: '#4338ca' },
  { range: '$100K+', count: 14, color: '#3730a3' },
]

const processingTrend = [
  { month: 'Mar', avgDays: 12.5, p90Days: 22 },
  { month: 'Apr', avgDays: 11.8, p90Days: 21 },
  { month: 'May', avgDays: 11.2, p90Days: 20 },
  { month: 'Jun', avgDays: 10.5, p90Days: 19 },
  { month: 'Jul', avgDays: 10.1, p90Days: 18 },
  { month: 'Aug', avgDays: 9.8, p90Days: 17 },
  { month: 'Sep', avgDays: 9.5, p90Days: 17 },
  { month: 'Oct', avgDays: 9.2, p90Days: 16 },
  { month: 'Nov', avgDays: 8.8, p90Days: 15 },
  { month: 'Dec', avgDays: 8.5, p90Days: 15 },
  { month: 'Jan', avgDays: 8.3, p90Days: 14 },
  { month: 'Feb', avgDays: 8.1, p90Days: 14 },
]

export default function SettlementAnalytics() {
  const totalSettled = 16246600
  const avgSettlement = 18350
  const avgProcessingDays = 8.3
  const customerSat = 4.6

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Settlement Analytics</h2>

      {/* KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        <KpiCard
          title="Total Settled (YTD)"
          value={`$${(totalSettled / 1000000).toFixed(1)}M`}
          icon={DollarSign}
          detail="+12.4% vs prior year"
          positive
        />
        <KpiCard
          title="Average Settlement"
          value={`$${avgSettlement.toLocaleString()}`}
          icon={TrendingUp}
          detail="Across all claim types"
        />
        <KpiCard
          title="Avg Processing Days"
          value={`${avgProcessingDays}`}
          icon={Clock}
          detail="-34% improvement YoY"
          positive
        />
        <KpiCard
          title="Customer Satisfaction"
          value={`${customerSat}/5.0`}
          icon={Star}
          detail="Based on 1,247 surveys"
          positive
        />
      </div>

      {/* Monthly Settlement Trend + Processing Time */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Monthly Settlement Volume & Amount</h3>
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={monthlySettlements}>
              <XAxis dataKey="month" stroke="#6b7280" fontSize={12} />
              <YAxis
                yAxisId="left"
                stroke="#6b7280"
                fontSize={12}
                tickFormatter={(v) => `$${(v / 1000000).toFixed(1)}M`}
              />
              <YAxis
                yAxisId="right"
                orientation="right"
                stroke="#6b7280"
                fontSize={12}
              />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                labelStyle={{ color: '#9ca3af' }}
                formatter={(value: number, name: string) => {
                  if (name === 'amount') return [`$${(value / 1000000).toFixed(2)}M`, 'Total Amount']
                  return [`${value}`, 'Claims Settled']
                }}
              />
              <Line yAxisId="left" type="monotone" dataKey="amount" stroke="#6366f1" strokeWidth={2} dot={false} />
              <Line yAxisId="right" type="monotone" dataKey="settled" stroke="#10b981" strokeWidth={2} dot={false} strokeDasharray="5 5" />
            </LineChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-6 mt-2 text-xs text-gray-500">
            <span><span className="inline-block w-4 h-0.5 bg-indigo-500 mr-1 align-middle" /> Total Amount</span>
            <span><span className="inline-block w-4 h-0.5 bg-green-500 mr-1 align-middle border-dashed" /> Claims Settled</span>
          </div>
        </div>

        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Processing Time Trend</h3>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={processingTrend}>
              <XAxis dataKey="month" stroke="#6b7280" fontSize={12} />
              <YAxis stroke="#6b7280" fontSize={12} tickFormatter={(v) => `${v}d`} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: number, name: string) => {
                  if (name === 'p90Days') return [`${value} days`, 'P90 Processing']
                  return [`${value} days`, 'Avg Processing']
                }}
              />
              <Area type="monotone" dataKey="p90Days" stroke="#4338ca" fill="#4338ca" fillOpacity={0.15} strokeWidth={1} strokeDasharray="4 4" />
              <Area type="monotone" dataKey="avgDays" stroke="#6366f1" fill="#6366f1" fillOpacity={0.25} strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-6 mt-2 text-xs text-gray-500">
            <span><span className="inline-block w-4 h-0.5 bg-indigo-500 mr-1 align-middle" /> Average</span>
            <span><span className="inline-block w-4 h-0.5 bg-indigo-800 mr-1 align-middle" /> P90</span>
          </div>
        </div>
      </div>

      {/* Settlement by Type + Amount Distribution */}
      <div className="grid grid-cols-2 gap-6">
        {/* Settlement by Claim Type */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Settlement by Claim Type</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={settlementByType} margin={{ left: 10 }}>
              <XAxis dataKey="type" stroke="#6b7280" fontSize={10} angle={-20} textAnchor="end" height={50} />
              <YAxis stroke="#6b7280" fontSize={12} tickFormatter={(v) => `$${(v / 1000000).toFixed(1)}M`} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: number, name: string) => {
                  if (name === 'totalAmount') return [`$${(value / 1000000).toFixed(2)}M`, 'Total Settled']
                  return [`${value}`, name]
                }}
              />
              <Bar dataKey="totalAmount" radius={[6, 6, 0, 0]}>
                {settlementByType.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="mt-4 space-y-2">
            {settlementByType.map((item) => (
              <div key={item.type} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full" style={{ background: item.color }} />
                  <span className="text-gray-400">{item.type}</span>
                </div>
                <div className="flex gap-4">
                  <span className="text-gray-500">{item.count} claims</span>
                  <span className="text-gray-300">avg ${item.avgAmount.toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Settlement Amount Distribution */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Settlement Amount Distribution</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={amountDistribution}>
              <XAxis dataKey="range" stroke="#6b7280" fontSize={12} />
              <YAxis stroke="#6b7280" fontSize={12} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: number) => [`${value} claims`, 'Count']}
              />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {amountDistribution.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>

          {/* Reserve Adequacy Gauge */}
          <div className="mt-6 pt-4 border-t border-gray-800">
            <h4 className="text-sm font-medium text-gray-400 mb-3">Reserve Adequacy</h4>
            <div className="flex items-center gap-4">
              <div className="flex-1">
                <div className="flex justify-between text-xs text-gray-500 mb-1">
                  <span>Under-Reserved</span>
                  <span>Adequate</span>
                  <span>Over-Reserved</span>
                </div>
                <div className="h-3 bg-gray-800 rounded-full overflow-hidden relative">
                  <div className="absolute inset-0 bg-gradient-to-r from-red-500 via-green-500 to-yellow-500 opacity-30" />
                  <div
                    className="absolute top-0 h-full w-1 bg-white rounded-full shadow-lg shadow-white/50"
                    style={{ left: '58%' }}
                  />
                </div>
              </div>
              <div className="text-right">
                <div className="text-lg font-bold text-green-400">102.3%</div>
                <div className="text-xs text-gray-500">Adequacy ratio</div>
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-2">
              Current reserves are slightly above incurred losses, indicating healthy reserve positioning.
              Target range: 98-105%.
            </p>
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
