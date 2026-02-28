import React from 'react'
import { Shield, AlertTriangle, Eye, TrendingDown } from 'lucide-react'
import {
  PieChart as RPieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis,
} from 'recharts'

const fraudRiskDistribution = [
  { name: 'Low', value: 542, color: '#10b981' },
  { name: 'Medium', value: 118, color: '#f59e0b' },
  { name: 'High', value: 42, color: '#f97316' },
  { name: 'Critical', value: 15, color: '#ef4444' },
]

const fraudTypeBreakdown = [
  { type: 'Staged Accidents', count: 18, amount: 342000 },
  { type: 'Inflated Claims', count: 24, amount: 285000 },
  { type: 'Phantom Damage', count: 12, amount: 198000 },
  { type: 'Identity Fraud', count: 8, amount: 156000 },
  { type: 'Provider Fraud', count: 6, amount: 420000 },
]

interface FlaggedClaim {
  id: string
  claimType: string
  riskScore: number
  indicators: string[]
  recommendedAction: string
  amount: number
  flaggedDate: string
}

const flaggedClaims: FlaggedClaim[] = [
  {
    id: 'CLM-2026-004',
    claimType: 'Auto Theft',
    riskScore: 92,
    indicators: ['Recent policy change', 'High-value vehicle', 'No police report within 24hrs'],
    recommendedAction: 'Full investigation - assign SIU',
    amount: 32000,
    flaggedDate: '2026-02-24',
  },
  {
    id: 'CLM-2026-017',
    claimType: 'Auto Collision',
    riskScore: 87,
    indicators: ['Multiple prior claims', 'Staged accident pattern', 'Inconsistent witness statements'],
    recommendedAction: 'SIU investigation with recorded statement',
    amount: 28500,
    flaggedDate: '2026-02-25',
  },
  {
    id: 'CLM-2026-022',
    claimType: 'Property Damage',
    riskScore: 78,
    indicators: ['Inflated repair estimate', 'Pre-existing damage suspected', 'Recently increased coverage'],
    recommendedAction: 'Independent adjuster reinspection',
    amount: 45000,
    flaggedDate: '2026-02-23',
  },
  {
    id: 'CLM-2026-031',
    claimType: 'Medical',
    riskScore: 74,
    indicators: ['Excessive treatment duration', 'Provider billing anomaly', 'Soft tissue only'],
    recommendedAction: 'Peer review of medical records',
    amount: 18200,
    flaggedDate: '2026-02-26',
  },
  {
    id: 'CLM-2026-038',
    claimType: 'Liability',
    riskScore: 68,
    indicators: ['Claimant linked to prior fraud ring', 'Attorney Letter of Representation on Day 1'],
    recommendedAction: 'Cross-reference with NICB database',
    amount: 22000,
    flaggedDate: '2026-02-27',
  },
  {
    id: 'CLM-2026-045',
    claimType: 'Water Damage',
    riskScore: 63,
    indicators: ['Claim amount exceeds property value ratio', 'No maintenance records'],
    recommendedAction: 'Detailed damage inspection',
    amount: 67000,
    flaggedDate: '2026-02-22',
  },
]

function getRiskColor(score: number): string {
  if (score >= 85) return 'text-red-400'
  if (score >= 70) return 'text-orange-400'
  if (score >= 50) return 'text-yellow-400'
  return 'text-green-400'
}

function getRiskBgColor(score: number): string {
  if (score >= 85) return 'bg-red-900/20 border-red-800/40'
  if (score >= 70) return 'bg-orange-900/20 border-orange-800/40'
  if (score >= 50) return 'bg-yellow-900/20 border-yellow-800/40'
  return 'bg-green-900/20 border-green-800/40'
}

export default function FraudAlerts() {
  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">Fraud Detection</h2>
        <div className="flex items-center gap-2 text-sm text-red-400">
          <AlertTriangle className="w-4 h-4" />
          6 active alerts
        </div>
      </div>

      {/* Fraud KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        <FraudKpiCard
          title="Detection Rate"
          value="97.3%"
          icon={Shield}
          detail="AI-assisted detection accuracy"
          color="text-green-400"
          borderColor="border-green-800/30"
        />
        <FraudKpiCard
          title="Savings (YTD)"
          value="$2.4M"
          icon={TrendingDown}
          detail="Prevented fraudulent payouts"
          color="text-emerald-400"
          borderColor="border-emerald-800/30"
        />
        <FraudKpiCard
          title="False Positive Rate"
          value="4.8%"
          icon={Eye}
          detail="Down from 7.2% last quarter"
          color="text-yellow-400"
          borderColor="border-yellow-800/30"
        />
        <FraudKpiCard
          title="Active Investigations"
          value="23"
          icon={AlertTriangle}
          detail="12 SIU, 11 desk review"
          color="text-red-400"
          borderColor="border-red-800/30"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-2 gap-6">
        {/* Risk Distribution Pie */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Fraud Risk Distribution</h3>
          <div className="flex items-center">
            <ResponsiveContainer width="60%" height={220}>
              <RPieChart>
                <Pie
                  data={fraudRiskDistribution}
                  dataKey="value"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={90}
                  paddingAngle={3}
                >
                  {fraudRiskDistribution.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                  formatter={(value: number) => [`${value} claims`, 'Count']}
                />
              </RPieChart>
            </ResponsiveContainer>
            <div className="flex-1 space-y-3">
              {fraudRiskDistribution.map((item) => (
                <div key={item.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full" style={{ background: item.color }} />
                    <span className="text-sm text-gray-400">{item.name}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-sm font-medium text-white">{item.value}</span>
                    <span className="text-xs text-gray-500 ml-1">
                      ({((item.value / 717) * 100).toFixed(1)}%)
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Fraud Type Breakdown */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Fraud Type Breakdown</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={fraudTypeBreakdown} layout="vertical" margin={{ left: 110 }}>
              <XAxis type="number" stroke="#6b7280" fontSize={12} />
              <YAxis type="category" dataKey="type" stroke="#6b7280" fontSize={11} width={110} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: number, name: string) => {
                  if (name === 'count') return [`${value} cases`, 'Cases']
                  return [`$${value.toLocaleString()}`, 'Est. Exposure']
                }}
              />
              <Bar dataKey="count" fill="#f97316" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Flagged Claims List */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h3 className="text-sm font-medium text-gray-400">Flagged Claims</h3>
          <span className="text-xs text-gray-500">Sorted by risk score (highest first)</span>
        </div>
        <div className="divide-y divide-gray-800/50">
          {flaggedClaims.map((claim) => (
            <div key={claim.id} className="px-6 py-4 hover:bg-gray-800/30 transition-colors">
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-3">
                  <div className={`w-12 h-12 rounded-lg flex items-center justify-center border ${getRiskBgColor(claim.riskScore)}`}>
                    <span className={`text-lg font-bold ${getRiskColor(claim.riskScore)}`}>{claim.riskScore}</span>
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-indigo-400">{claim.id}</span>
                      <span className="text-sm text-gray-400">{claim.claimType}</span>
                    </div>
                    <div className="text-xs text-gray-500 mt-0.5">
                      Flagged {claim.flaggedDate} | ${claim.amount.toLocaleString()}
                    </div>
                  </div>
                </div>
                <div className={`px-3 py-1 rounded-full text-xs font-medium border ${getRiskBgColor(claim.riskScore)} ${getRiskColor(claim.riskScore)}`}>
                  Risk: {claim.riskScore >= 85 ? 'Critical' : claim.riskScore >= 70 ? 'High' : 'Medium'}
                </div>
              </div>
              <div className="ml-15 pl-[60px]">
                <div className="flex flex-wrap gap-1.5 mb-2">
                  {claim.indicators.map((indicator, i) => (
                    <span key={i} className="px-2 py-0.5 text-xs bg-gray-800 text-gray-300 rounded border border-gray-700">
                      {indicator}
                    </span>
                  ))}
                </div>
                <div className="text-sm text-yellow-400/80">
                  <span className="text-gray-500">Recommended: </span>{claim.recommendedAction}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function FraudKpiCard({ title, value, icon: Icon, detail, color, borderColor }: {
  title: string; value: string; icon: React.ElementType; detail: string; color: string; borderColor: string
}) {
  return (
    <div className={`bg-gray-900 rounded-xl p-5 border ${borderColor}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-sm text-gray-500 mt-1">{detail}</div>
    </div>
  )
}
