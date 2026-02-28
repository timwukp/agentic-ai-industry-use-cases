import React from 'react'
import { FileText, Clock, CheckCircle, AlertTriangle } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const pipelineData = [
  { stage: 'Submitted', count: 142, color: '#818cf8' },
  { stage: 'Under Review', count: 98, color: '#6366f1' },
  { stage: 'Investigation', count: 45, color: '#4f46e5' },
  { stage: 'Assessment', count: 67, color: '#4338ca' },
  { stage: 'Settlement', count: 53, color: '#3730a3' },
  { stage: 'Closed', count: 312, color: '#312e81' },
]

interface Claim {
  id: string
  type: string
  status: string
  filedDate: string
  amount: number
  priority: string
  fraudRisk: string
}

const recentClaims: Claim[] = [
  { id: 'CLM-2026-001', type: 'Auto Collision', status: 'Under Review', filedDate: '2026-02-26', amount: 12500, priority: 'High', fraudRisk: 'Low' },
  { id: 'CLM-2026-002', type: 'Property Damage', status: 'Investigation', filedDate: '2026-02-25', amount: 45000, priority: 'Critical', fraudRisk: 'Medium' },
  { id: 'CLM-2026-003', type: 'Liability', status: 'Submitted', filedDate: '2026-02-27', amount: 8200, priority: 'Medium', fraudRisk: 'Low' },
  { id: 'CLM-2026-004', type: 'Auto Theft', status: 'Investigation', filedDate: '2026-02-24', amount: 32000, priority: 'High', fraudRisk: 'High' },
  { id: 'CLM-2026-005', type: 'Water Damage', status: 'Assessment', filedDate: '2026-02-23', amount: 18750, priority: 'Medium', fraudRisk: 'Low' },
  { id: 'CLM-2026-006', type: 'Auto Collision', status: 'Settlement', filedDate: '2026-02-20', amount: 6800, priority: 'Low', fraudRisk: 'Low' },
  { id: 'CLM-2026-007', type: 'Fire Damage', status: 'Under Review', filedDate: '2026-02-22', amount: 125000, priority: 'Critical', fraudRisk: 'Medium' },
  { id: 'CLM-2026-008', type: 'Medical', status: 'Assessment', filedDate: '2026-02-21', amount: 22400, priority: 'High', fraudRisk: 'Low' },
  { id: 'CLM-2026-009', type: 'Liability', status: 'Closed', filedDate: '2026-02-15', amount: 15600, priority: 'Medium', fraudRisk: 'Low' },
  { id: 'CLM-2026-010', type: 'Auto Collision', status: 'Submitted', filedDate: '2026-02-28', amount: 9300, priority: 'Medium', fraudRisk: 'Low' },
]

const statusColors: Record<string, string> = {
  'Submitted': 'bg-blue-900/30 text-blue-400 border-blue-800/50',
  'Under Review': 'bg-yellow-900/30 text-yellow-400 border-yellow-800/50',
  'Investigation': 'bg-orange-900/30 text-orange-400 border-orange-800/50',
  'Assessment': 'bg-purple-900/30 text-purple-400 border-purple-800/50',
  'Settlement': 'bg-indigo-900/30 text-indigo-400 border-indigo-800/50',
  'Closed': 'bg-green-900/30 text-green-400 border-green-800/50',
}

const priorityColors: Record<string, string> = {
  'Low': 'text-gray-400',
  'Medium': 'text-yellow-400',
  'High': 'text-orange-400',
  'Critical': 'text-red-400',
}

const fraudRiskColors: Record<string, string> = {
  'Low': 'text-green-400',
  'Medium': 'text-yellow-400',
  'High': 'text-red-400',
}

export default function ClaimsDashboard() {
  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Claims Dashboard</h2>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard title="Total Claims" value="717" icon={FileText} change="+24 this week" />
        <StatCard title="Open Claims" value="405" icon={AlertTriangle} change="56.5% of total" highlight />
        <StatCard title="Avg Processing Time" value="8.3 days" icon={Clock} change="-1.2 days vs last month" positive />
        <StatCard title="Settlement Rate" value="94.2%" icon={CheckCircle} change="+2.1% vs last quarter" positive />
      </div>

      {/* Claims Pipeline */}
      <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
        <h3 className="text-sm font-medium text-gray-400 mb-4">Claims Pipeline</h3>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={pipelineData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
            <XAxis dataKey="stage" stroke="#6b7280" fontSize={12} />
            <YAxis stroke="#6b7280" fontSize={12} />
            <Tooltip
              contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
              labelStyle={{ color: '#9ca3af' }}
              formatter={(value: number) => [`${value} claims`, 'Count']}
            />
            <Bar dataKey="count" radius={[6, 6, 0, 0]}>
              {pipelineData.map((entry, i) => (
                <Cell key={i} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Recent Claims Table */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h3 className="text-sm font-medium text-gray-400">Recent Claims</h3>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 text-left">Claim ID</th>
              <th className="px-6 py-3 text-left">Type</th>
              <th className="px-6 py-3 text-left">Status</th>
              <th className="px-6 py-3 text-left">Filed Date</th>
              <th className="px-6 py-3 text-right">Amount</th>
              <th className="px-6 py-3 text-center">Priority</th>
              <th className="px-6 py-3 text-center">Fraud Risk</th>
            </tr>
          </thead>
          <tbody>
            {recentClaims.map((claim) => (
              <tr key={claim.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-6 py-3">
                  <span className="font-medium text-indigo-400">{claim.id}</span>
                </td>
                <td className="px-6 py-3 text-gray-300 text-sm">{claim.type}</td>
                <td className="px-6 py-3">
                  <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border ${statusColors[claim.status]}`}>
                    {claim.status}
                  </span>
                </td>
                <td className="px-6 py-3 text-gray-400 text-sm">{claim.filedDate}</td>
                <td className="px-6 py-3 text-right text-white font-medium">${claim.amount.toLocaleString()}</td>
                <td className="px-6 py-3 text-center">
                  <span className={`text-sm font-medium ${priorityColors[claim.priority]}`}>{claim.priority}</span>
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`text-sm font-medium ${fraudRiskColors[claim.fraudRisk]}`}>{claim.fraudRisk}</span>
                </td>
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
    <div className={`bg-gray-900 rounded-xl p-5 border ${highlight ? 'border-indigo-800/50' : 'border-gray-800'}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className="w-5 h-5 text-gray-500" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className={`text-sm mt-1 ${positive ? 'text-green-400' : 'text-gray-400'}`}>{change}</div>
    </div>
  )
}
