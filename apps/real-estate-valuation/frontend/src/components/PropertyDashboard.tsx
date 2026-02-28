import React from 'react'
import { Home, DollarSign, Ruler, Thermometer, Search } from 'lucide-react'
import {
  PieChart as RPieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis,
} from 'recharts'

const propertyTypeData = [
  { name: 'Single Family', count: 142, color: '#06b6d4' },
  { name: 'Condo', count: 87, color: '#22d3ee' },
  { name: 'Multi-Family', count: 43, color: '#0e7490' },
  { name: 'Commercial', count: 28, color: '#155e75' },
  { name: 'Land', count: 15, color: '#67e8f9' },
]

const valueRangeData = [
  { range: '$0-200K', count: 32, color: '#67e8f9' },
  { range: '$200-400K', count: 78, color: '#22d3ee' },
  { range: '$400-600K', count: 95, color: '#06b6d4' },
  { range: '$600-800K', count: 62, color: '#0891b2' },
  { range: '$800K-1M', count: 31, color: '#0e7490' },
  { range: '$1M+', count: 17, color: '#155e75' },
]

interface Valuation {
  address: string
  type: string
  beds: number
  baths: number
  sqft: number
  estimatedValue: number
  confidence: number
  date: string
}

const recentValuations: Valuation[] = [
  { address: '123 Oak Street, Austin TX', type: 'Single Family', beds: 4, baths: 3, sqft: 2850, estimatedValue: 685000, confidence: 94, date: '2026-02-27' },
  { address: '456 Maple Ave, Denver CO', type: 'Condo', beds: 2, baths: 2, sqft: 1200, estimatedValue: 425000, confidence: 91, date: '2026-02-27' },
  { address: '789 Pine Rd, Seattle WA', type: 'Single Family', beds: 3, baths: 2, sqft: 1980, estimatedValue: 820000, confidence: 88, date: '2026-02-26' },
  { address: '321 Elm Blvd, Miami FL', type: 'Multi-Family', beds: 6, baths: 4, sqft: 3400, estimatedValue: 1250000, confidence: 85, date: '2026-02-26' },
  { address: '654 Cedar Ln, Phoenix AZ', type: 'Single Family', beds: 3, baths: 2, sqft: 1750, estimatedValue: 380000, confidence: 93, date: '2026-02-25' },
  { address: '987 Birch Way, Nashville TN', type: 'Condo', beds: 1, baths: 1, sqft: 850, estimatedValue: 295000, confidence: 90, date: '2026-02-25' },
  { address: '246 Walnut Dr, Portland OR', type: 'Single Family', beds: 4, baths: 3, sqft: 2400, estimatedValue: 715000, confidence: 87, date: '2026-02-24' },
  { address: '135 Spruce Ct, Charlotte NC', type: 'Commercial', beds: 0, baths: 2, sqft: 5200, estimatedValue: 1850000, confidence: 82, date: '2026-02-24' },
]

function getConfidenceColor(confidence: number): string {
  if (confidence >= 90) return 'text-green-400'
  if (confidence >= 85) return 'text-cyan-400'
  return 'text-yellow-400'
}

function getConfidenceBg(confidence: number): string {
  if (confidence >= 90) return 'bg-green-900/20'
  if (confidence >= 85) return 'bg-cyan-900/20'
  return 'bg-yellow-900/20'
}

export default function PropertyDashboard() {
  const totalProperties = propertyTypeData.reduce((sum, d) => sum + d.count, 0)

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Property Dashboard</h2>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard title="Properties Analyzed" value="315" icon={Home} change="+23 this week" positive />
        <StatCard title="Avg Home Value" value="$542K" icon={DollarSign} change="+4.2% vs last quarter" positive />
        <StatCard title="Median Price/SqFt" value="$287" icon={Ruler} change="Across all property types" />
        <StatCard title="Market Temp" value="Hot" icon={Thermometer} change="Strong seller's market" highlight />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-2 gap-6">
        {/* Property Type Distribution Donut */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Property Type Distribution</h3>
          <div className="flex items-center">
            <ResponsiveContainer width="55%" height={240}>
              <RPieChart>
                <Pie
                  data={propertyTypeData}
                  dataKey="count"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={90}
                  paddingAngle={3}
                >
                  {propertyTypeData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                  formatter={(value: unknown) => [`${Number(value)} properties`, 'Count']}
                />
              </RPieChart>
            </ResponsiveContainer>
            <div className="flex-1 space-y-3">
              {propertyTypeData.map((item) => (
                <div key={item.name}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full" style={{ background: item.color }} />
                      <span className="text-sm font-medium text-gray-300">{item.name}</span>
                    </div>
                    <span className="text-sm font-bold text-white">{item.count}</span>
                  </div>
                  <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${(item.count / totalProperties) * 100}%`, background: item.color }}
                    />
                  </div>
                  <div className="text-[10px] text-gray-600 mt-0.5">
                    {((item.count / totalProperties) * 100).toFixed(1)}% of total
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Value Range Distribution Histogram */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Value Range Distribution</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={valueRangeData} margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
              <XAxis dataKey="range" stroke="#6b7280" fontSize={11} />
              <YAxis stroke="#6b7280" fontSize={12} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: unknown) => [`${Number(value)} properties`, 'Count']}
              />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {valueRangeData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Valuations Table */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-medium text-gray-400">Recent Valuations</h3>
          </div>
          <span className="text-xs text-gray-500">{recentValuations.length} valuations this week</span>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 text-left">Address</th>
              <th className="px-6 py-3 text-left">Type</th>
              <th className="px-6 py-3 text-center">Beds/Baths</th>
              <th className="px-6 py-3 text-right">SqFt</th>
              <th className="px-6 py-3 text-right">Estimated Value</th>
              <th className="px-6 py-3 text-center">Confidence</th>
              <th className="px-6 py-3 text-right">Date</th>
            </tr>
          </thead>
          <tbody>
            {recentValuations.map((item) => (
              <tr key={item.address} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-6 py-3">
                  <span className="font-medium text-cyan-400">{item.address}</span>
                </td>
                <td className="px-6 py-3">
                  <span className="text-sm text-gray-300">{item.type}</span>
                </td>
                <td className="px-6 py-3 text-center text-sm text-gray-300">
                  {item.beds > 0 ? `${item.beds}bd / ${item.baths}ba` : `${item.baths}ba`}
                </td>
                <td className="px-6 py-3 text-right text-sm text-gray-400">
                  {item.sqft.toLocaleString()}
                </td>
                <td className="px-6 py-3 text-right">
                  <span className="font-medium text-white">${(item.estimatedValue / 1000).toFixed(0)}K</span>
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`inline-flex items-center justify-center w-12 h-8 rounded-lg text-sm font-bold ${getConfidenceColor(item.confidence)} ${getConfidenceBg(item.confidence)}`}>
                    {item.confidence}%
                  </span>
                </td>
                <td className="px-6 py-3 text-right text-sm text-gray-500">{item.date}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon: Icon, change, positive, highlight }: {
  title: string; value: string; icon: React.ElementType; change: string; positive?: boolean; highlight?: boolean
}) {
  return (
    <div className={`bg-gray-900 rounded-xl p-5 border ${highlight ? 'border-cyan-800/50' : 'border-gray-800'}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className="w-5 h-5 text-gray-500" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className={`text-sm mt-1 ${positive ? 'text-green-400' : 'text-gray-400'}`}>{change}</div>
    </div>
  )
}
