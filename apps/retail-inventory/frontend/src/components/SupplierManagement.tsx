import React from 'react'
import { Users, Star, Clock, FileText, AlertTriangle, Globe, ShieldCheck, ShieldAlert } from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'

interface Supplier {
  name: string
  score: number
  onTime: number
  quality: number
  leadTime: number
  status: string
  ytdSpend: number
  region: string
}

const suppliers: Supplier[] = [
  { name: 'TechParts Global', score: 94, onTime: 97, quality: 99, leadTime: 5, status: 'Preferred', ytdSpend: 1250000, region: 'Asia Pacific' },
  { name: 'Apex Electronics', score: 91, onTime: 95, quality: 98, leadTime: 7, status: 'Preferred', ytdSpend: 980000, region: 'North America' },
  { name: 'FabricWorld Inc', score: 87, onTime: 90, quality: 96, leadTime: 12, status: 'Approved', ytdSpend: 720000, region: 'Asia Pacific' },
  { name: 'GreenSource Organics', score: 85, onTime: 92, quality: 94, leadTime: 8, status: 'Approved', ytdSpend: 540000, region: 'South America' },
  { name: 'Pacific Packaging', score: 82, onTime: 88, quality: 95, leadTime: 10, status: 'Approved', ytdSpend: 430000, region: 'Asia Pacific' },
  { name: 'HomeGoods Direct', score: 78, onTime: 85, quality: 92, leadTime: 14, status: 'Probation', ytdSpend: 380000, region: 'Europe' },
  { name: 'SportGear Mfg', score: 76, onTime: 82, quality: 91, leadTime: 18, status: 'Probation', ytdSpend: 290000, region: 'Asia Pacific' },
  { name: 'QuickShip Logistics', score: 72, onTime: 78, quality: 89, leadTime: 15, status: 'Under Review', ytdSpend: 210000, region: 'North America' },
]

const statusColors: Record<string, string> = {
  'Preferred': 'bg-emerald-900/30 text-emerald-400 border-emerald-800/50',
  'Approved': 'bg-blue-900/30 text-blue-400 border-blue-800/50',
  'Probation': 'bg-yellow-900/30 text-yellow-400 border-yellow-800/50',
  'Under Review': 'bg-red-900/30 text-red-400 border-red-800/50',
}

const poPipeline = [
  { stage: 'Created', count: 42, color: '#6ee7b7' },
  { stage: 'Confirmed', count: 38, color: '#34d399' },
  { stage: 'Shipped', count: 27, color: '#10b981' },
  { stage: 'Delivered', count: 156, color: '#059669' },
]

interface RiskItem {
  category: string
  level: string
  description: string
  affectedSuppliers: number
  mitigation: string
}

const riskAssessment: RiskItem[] = [
  { category: 'Single Source Dependency', level: 'High', description: '3 critical SKUs depend on single supplier TechParts Global', affectedSuppliers: 1, mitigation: 'Qualify secondary supplier by Q2' },
  { category: 'Geopolitical Risk', level: 'Medium', description: '62% of spend concentrated in Asia Pacific region', affectedSuppliers: 4, mitigation: 'Diversify to nearshore suppliers' },
  { category: 'Lead Time Volatility', level: 'Medium', description: 'HomeGoods Direct and SportGear Mfg showing +40% lead time variance', affectedSuppliers: 2, mitigation: 'Increase safety stock for affected SKUs' },
  { category: 'Quality Trend', level: 'Low', description: 'QuickShip Logistics quality score declining 3 consecutive months', affectedSuppliers: 1, mitigation: 'Schedule quality audit and corrective action plan' },
  { category: 'Financial Health', level: 'Low', description: 'All suppliers within acceptable financial stability range', affectedSuppliers: 0, mitigation: 'Continue quarterly financial reviews' },
]

const riskLevelColors: Record<string, { text: string; bg: string; border: string; icon: React.ElementType }> = {
  'High': { text: 'text-red-400', bg: 'bg-red-900/20', border: 'border-red-800/40', icon: ShieldAlert },
  'Medium': { text: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-800/40', icon: AlertTriangle },
  'Low': { text: 'text-green-400', bg: 'bg-green-900/20', border: 'border-green-800/40', icon: ShieldCheck },
}

interface RegionData {
  region: string
  supplierCount: number
  totalSpend: number
  avgScore: number
}

const regionData: RegionData[] = [
  { region: 'Asia Pacific', supplierCount: 4, totalSpend: 2900000, avgScore: 85 },
  { region: 'North America', supplierCount: 2, totalSpend: 1190000, avgScore: 82 },
  { region: 'Europe', supplierCount: 1, totalSpend: 380000, avgScore: 78 },
  { region: 'South America', supplierCount: 1, totalSpend: 540000, avgScore: 85 },
]

function getScoreColor(score: number): string {
  if (score >= 90) return 'text-emerald-400'
  if (score >= 80) return 'text-yellow-400'
  if (score >= 70) return 'text-orange-400'
  return 'text-red-400'
}

export default function SupplierManagement() {
  const totalSuppliers = suppliers.length
  const avgScore = Math.round(suppliers.reduce((sum, s) => sum + s.score, 0) / totalSuppliers)
  const avgOnTime = Math.round(suppliers.reduce((sum, s) => sum + s.onTime, 0) / totalSuppliers * 10) / 10
  const activePOs = poPipeline.reduce((sum, p) => sum + p.count, 0) - poPipeline[3].count // exclude delivered

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Supplier Management</h2>

      {/* KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        <KpiCard title="Total Suppliers" value={`${totalSuppliers}`} icon={Users} detail="4 preferred, 2 approved" />
        <KpiCard title="Avg Score" value={`${avgScore}/100`} icon={Star} detail="Weighted by spend volume" positive />
        <KpiCard title="On-Time Rate" value={`${avgOnTime}%`} icon={Clock} detail="+2.3% vs last quarter" positive />
        <KpiCard title="Active POs" value={`${activePOs}`} icon={FileText} detail="107 orders in pipeline" />
      </div>

      {/* Supplier Scorecard Table */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h3 className="text-sm font-medium text-gray-400">Supplier Scorecard</h3>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 text-left">Supplier</th>
              <th className="px-6 py-3 text-center">Score</th>
              <th className="px-6 py-3 text-center">On-Time %</th>
              <th className="px-6 py-3 text-center">Quality %</th>
              <th className="px-6 py-3 text-center">Lead Time</th>
              <th className="px-6 py-3 text-center">Status</th>
              <th className="px-6 py-3 text-right">YTD Spend</th>
            </tr>
          </thead>
          <tbody>
            {suppliers.map((supplier) => (
              <tr key={supplier.name} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-6 py-3">
                  <div className="font-medium text-emerald-400">{supplier.name}</div>
                  <div className="text-xs text-gray-500">{supplier.region}</div>
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`text-lg font-bold ${getScoreColor(supplier.score)}`}>{supplier.score}</span>
                </td>
                <td className="px-6 py-3 text-center">
                  <div className="flex flex-col items-center">
                    <span className={`text-sm font-medium ${supplier.onTime >= 90 ? 'text-green-400' : supplier.onTime >= 80 ? 'text-yellow-400' : 'text-red-400'}`}>
                      {supplier.onTime}%
                    </span>
                    <div className="w-16 h-1.5 bg-gray-800 rounded-full mt-1 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${supplier.onTime >= 90 ? 'bg-green-500' : supplier.onTime >= 80 ? 'bg-yellow-500' : 'bg-red-500'}`}
                        style={{ width: `${supplier.onTime}%` }}
                      />
                    </div>
                  </div>
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`text-sm font-medium ${supplier.quality >= 95 ? 'text-green-400' : supplier.quality >= 90 ? 'text-yellow-400' : 'text-red-400'}`}>
                    {supplier.quality}%
                  </span>
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`text-sm ${supplier.leadTime <= 7 ? 'text-green-400' : supplier.leadTime <= 14 ? 'text-yellow-400' : 'text-red-400'}`}>
                    {supplier.leadTime} days
                  </span>
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border ${statusColors[supplier.status]}`}>
                    {supplier.status}
                  </span>
                </td>
                <td className="px-6 py-3 text-right text-white font-medium">
                  ${(supplier.ytdSpend / 1000).toFixed(0)}K
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Risk Assessment + PO Pipeline */}
      <div className="grid grid-cols-2 gap-6">
        {/* Supplier Risk Assessment */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-medium text-gray-400">Risk Assessment Summary</h3>
          </div>
          <div className="divide-y divide-gray-800/50">
            {riskAssessment.map((risk) => {
              const riskStyle = riskLevelColors[risk.level]
              const RiskIcon = riskStyle.icon
              return (
                <div key={risk.category} className="px-6 py-4 hover:bg-gray-800/30">
                  <div className="flex items-start gap-3">
                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${riskStyle.bg} border ${riskStyle.border} flex-shrink-0 mt-0.5`}>
                      <RiskIcon className={`w-4 h-4 ${riskStyle.text}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-gray-200">{risk.category}</span>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${riskStyle.text} ${riskStyle.bg} border ${riskStyle.border}`}>
                          {risk.level}
                        </span>
                      </div>
                      <p className="text-xs text-gray-400 mb-1">{risk.description}</p>
                      <p className="text-xs text-emerald-400/80">
                        <span className="text-gray-500">Mitigation: </span>{risk.mitigation}
                      </p>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* PO Pipeline + Geographic Distribution */}
        <div className="space-y-6">
          {/* PO Pipeline Chart */}
          <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
            <h3 className="text-sm font-medium text-gray-400 mb-4">Purchase Order Pipeline</h3>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={poPipeline} margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
                <XAxis dataKey="stage" stroke="#6b7280" fontSize={12} />
                <YAxis stroke="#6b7280" fontSize={12} />
                <Tooltip
                  contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                  formatter={(value: number) => [`${value} orders`, 'Count']}
                />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {poPipeline.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Geographic Supplier Distribution */}
          <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
              <Globe className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-medium text-gray-400">Geographic Distribution</h3>
            </div>
            <div className="divide-y divide-gray-800/50">
              {regionData.map((region) => (
                <div key={region.region} className="px-6 py-3 flex items-center justify-between hover:bg-gray-800/30">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-emerald-900/30 rounded-lg flex items-center justify-center">
                      <span className="text-sm font-bold text-emerald-400">{region.supplierCount}</span>
                    </div>
                    <div>
                      <div className="text-sm text-gray-200">{region.region}</div>
                      <div className="text-xs text-gray-500">Avg score: {region.avgScore}</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium text-white">${(region.totalSpend / 1000000).toFixed(1)}M</div>
                    <div className="text-xs text-gray-500">
                      {((region.totalSpend / 5010000) * 100).toFixed(0)}% of spend
                    </div>
                  </div>
                </div>
              ))}
            </div>
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
