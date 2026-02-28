import React from 'react'
import { Percent, TrendingUp, BarChart3, Wallet, Star } from 'lucide-react'
import {
  Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, Legend,
  AreaChart, Area,
} from 'recharts'

const cashFlowWaterfall = [
  { name: 'Gross Rent', value: 84000, total: 84000, color: '#06b6d4' },
  { name: 'Vacancy', value: -4200, total: 79800, color: '#ef4444' },
  { name: 'Opex', value: -22400, total: 57400, color: '#ef4444' },
  { name: 'Debt Service', value: -31200, total: 26200, color: '#f59e0b' },
  { name: 'Net Cash Flow', value: 26200, total: 26200, color: '#10b981' },
]

const roiProjection = [
  { year: 'Year 0', equity: 100000, appreciation: 0, cashFlow: 0, total: 100000 },
  { year: 'Year 1', equity: 108500, appreciation: 17500, cashFlow: 26200, total: 152200 },
  { year: 'Year 2', equity: 117400, appreciation: 36200, cashFlow: 53600, total: 207200 },
  { year: 'Year 3', equity: 126800, appreciation: 56200, cashFlow: 82300, total: 265300 },
  { year: 'Year 4', equity: 136700, appreciation: 77500, cashFlow: 112400, total: 326600 },
  { year: 'Year 5', equity: 147200, appreciation: 100200, cashFlow: 144000, total: 391400 },
]

interface InvestmentProperty {
  address: string
  purchasePrice: number
  rentalIncome: number
  noi: number
  capRate: number
  cashOnCash: number
  roi: number
}

const investmentProperties: InvestmentProperty[] = [
  { address: '415 River Rd, Austin TX', purchasePrice: 500000, rentalIncome: 84000, noi: 57400, capRate: 11.5, cashOnCash: 13.1, roi: 18.4 },
  { address: '228 Lake View Dr, Denver CO', purchasePrice: 425000, rentalIncome: 54000, noi: 36800, capRate: 8.7, cashOnCash: 9.2, roi: 14.6 },
  { address: '789 Mountain Ave, Seattle WA', purchasePrice: 680000, rentalIncome: 72000, noi: 48200, capRate: 7.1, cashOnCash: 7.8, roi: 13.2 },
  { address: '1020 Palm Blvd, Miami FL', purchasePrice: 750000, rentalIncome: 96000, noi: 65400, capRate: 8.7, cashOnCash: 10.5, roi: 16.1 },
  { address: '562 Desert Way, Phoenix AZ', purchasePrice: 320000, rentalIncome: 42000, noi: 29400, capRate: 9.2, cashOnCash: 11.7, roi: 15.8 },
  { address: '331 Music Row, Nashville TN', purchasePrice: 445000, rentalIncome: 60000, noi: 40800, capRate: 9.2, cashOnCash: 10.2, roi: 14.9 },
]

interface ScoredProperty {
  address: string
  overallScore: number
  cashFlowScore: number
  appreciationScore: number
  riskScore: number
  recommendation: string
}

const scoredProperties: ScoredProperty[] = [
  { address: '415 River Rd, Austin TX', overallScore: 92, cashFlowScore: 95, appreciationScore: 88, riskScore: 90, recommendation: 'Strong Buy' },
  { address: '1020 Palm Blvd, Miami FL', overallScore: 87, cashFlowScore: 90, appreciationScore: 85, riskScore: 82, recommendation: 'Buy' },
  { address: '562 Desert Way, Phoenix AZ', overallScore: 84, cashFlowScore: 82, appreciationScore: 88, riskScore: 80, recommendation: 'Buy' },
  { address: '331 Music Row, Nashville TN', overallScore: 81, cashFlowScore: 78, appreciationScore: 85, riskScore: 79, recommendation: 'Hold' },
]

function getScoreColor(score: number): string {
  if (score >= 90) return 'text-green-400'
  if (score >= 80) return 'text-cyan-400'
  if (score >= 70) return 'text-yellow-400'
  return 'text-red-400'
}

function getScoreBg(score: number): string {
  if (score >= 90) return 'bg-green-900/20'
  if (score >= 80) return 'bg-cyan-900/20'
  if (score >= 70) return 'bg-yellow-900/20'
  return 'bg-red-900/20'
}

const recommendationColors: Record<string, string> = {
  'Strong Buy': 'bg-green-900/30 text-green-400 border-green-800/50',
  'Buy': 'bg-cyan-900/30 text-cyan-400 border-cyan-800/50',
  'Hold': 'bg-yellow-900/30 text-yellow-400 border-yellow-800/50',
  'Sell': 'bg-red-900/30 text-red-400 border-red-800/50',
}

export default function InvestmentAnalysis() {
  const avgCapRate = (investmentProperties.reduce((s, p) => s + p.capRate, 0) / investmentProperties.length).toFixed(1)
  const avgCashOnCash = (investmentProperties.reduce((s, p) => s + p.cashOnCash, 0) / investmentProperties.length).toFixed(1)
  const avgROI = (investmentProperties.reduce((s, p) => s + p.roi, 0) / investmentProperties.length).toFixed(1)
  const totalPortfolio = investmentProperties.reduce((s, p) => s + p.purchasePrice, 0)

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Investment Analysis</h2>

      {/* KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        <KpiCard title="Avg Cap Rate" value={`${avgCapRate}%`} icon={Percent} detail="Across 6 properties" positive />
        <KpiCard title="Cash-on-Cash Return" value={`${avgCashOnCash}%`} icon={TrendingUp} detail="Avg annual return" positive />
        <KpiCard title="Avg ROI" value={`${avgROI}%`} icon={BarChart3} detail="Including appreciation" positive />
        <KpiCard title="Total Portfolio Value" value={`$${(totalPortfolio / 1000000).toFixed(1)}M`} icon={Wallet} detail="6 investment properties" highlight />
      </div>

      {/* Property Comparison Table */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h3 className="text-sm font-medium text-gray-400">Property Comparison</h3>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 text-left">Address</th>
              <th className="px-6 py-3 text-right">Purchase Price</th>
              <th className="px-6 py-3 text-right">Rental Income</th>
              <th className="px-6 py-3 text-right">NOI</th>
              <th className="px-6 py-3 text-center">Cap Rate</th>
              <th className="px-6 py-3 text-center">Cash-on-Cash</th>
              <th className="px-6 py-3 text-center">ROI</th>
            </tr>
          </thead>
          <tbody>
            {investmentProperties.map((prop) => (
              <tr key={prop.address} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-6 py-3">
                  <span className="font-medium text-cyan-400">{prop.address}</span>
                </td>
                <td className="px-6 py-3 text-right text-white font-medium">
                  ${(prop.purchasePrice / 1000).toFixed(0)}K
                </td>
                <td className="px-6 py-3 text-right text-gray-300">
                  ${(prop.rentalIncome / 1000).toFixed(0)}K/yr
                </td>
                <td className="px-6 py-3 text-right text-gray-300">
                  ${(prop.noi / 1000).toFixed(1)}K
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`font-bold ${prop.capRate >= 9 ? 'text-green-400' : prop.capRate >= 7 ? 'text-cyan-400' : 'text-yellow-400'}`}>
                    {prop.capRate}%
                  </span>
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`font-bold ${prop.cashOnCash >= 10 ? 'text-green-400' : prop.cashOnCash >= 8 ? 'text-cyan-400' : 'text-yellow-400'}`}>
                    {prop.cashOnCash}%
                  </span>
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`font-bold ${prop.roi >= 15 ? 'text-green-400' : prop.roi >= 12 ? 'text-cyan-400' : 'text-yellow-400'}`}>
                    {prop.roi}%
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Cash Flow Waterfall + ROI Projection */}
      <div className="grid grid-cols-2 gap-6">
        {/* Cash Flow Waterfall */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Annual Cash Flow Waterfall</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={cashFlowWaterfall} margin={{ top: 5, right: 20, left: 20, bottom: 5 }}>
              <XAxis dataKey="name" stroke="#6b7280" fontSize={11} />
              <YAxis stroke="#6b7280" fontSize={12} tickFormatter={(v: number) => `$${(v / 1000).toFixed(0)}K`} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: unknown, name: string) => {
                  const numValue = Number(value)
                  if (name === 'value') {
                    const prefix = numValue >= 0 ? '+' : ''
                    return [`${prefix}$${(numValue / 1000).toFixed(1)}K`, 'Amount']
                  }
                  return [`$${(numValue / 1000).toFixed(1)}K`, 'Running Total']
                }}
              />
              <Bar dataKey="total" radius={[6, 6, 0, 0]}>
                {cashFlowWaterfall.map((entry, i) => (
                  <Cell key={i} fill={entry.color} fillOpacity={0.8} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-4 mt-2 text-xs text-gray-500">
            <span><span className="inline-block w-3 h-3 bg-cyan-500 rounded-sm mr-1 align-middle" /> Income</span>
            <span><span className="inline-block w-3 h-3 bg-red-500 rounded-sm mr-1 align-middle" /> Expense</span>
            <span><span className="inline-block w-3 h-3 bg-yellow-500 rounded-sm mr-1 align-middle" /> Debt Service</span>
            <span><span className="inline-block w-3 h-3 bg-green-500 rounded-sm mr-1 align-middle" /> Net Cash Flow</span>
          </div>
        </div>

        {/* 5-Year ROI Projection */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">5-Year ROI Projection</h3>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={roiProjection} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
              <XAxis dataKey="year" stroke="#6b7280" fontSize={12} />
              <YAxis stroke="#6b7280" fontSize={12} tickFormatter={(v: number) => `$${(v / 1000).toFixed(0)}K`} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                labelStyle={{ color: '#9ca3af' }}
                formatter={(value: unknown, name: string) => {
                  const numValue = Number(value)
                  const labels: Record<string, string> = {
                    equity: 'Equity Buildup',
                    appreciation: 'Appreciation',
                    cashFlow: 'Cumulative Cash Flow',
                    total: 'Total Value',
                  }
                  return [`$${(numValue / 1000).toFixed(1)}K`, labels[name] || name]
                }}
              />
              <Legend
                formatter={(value: unknown) => {
                  const labels: Record<string, string> = {
                    equity: 'Equity Buildup',
                    appreciation: 'Appreciation',
                    cashFlow: 'Cash Flow',
                    total: 'Total Value',
                  }
                  return <span className="text-xs text-gray-400">{labels[String(value)] || String(value)}</span>
                }}
              />
              <defs>
                <linearGradient id="equityGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="appreciationGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="cashFlowGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <Area type="monotone" dataKey="equity" stroke="#06b6d4" fill="url(#equityGrad)" strokeWidth={2} dot={{ r: 3, fill: '#06b6d4' }} />
              <Area type="monotone" dataKey="appreciation" stroke="#10b981" fill="url(#appreciationGrad)" strokeWidth={2} dot={{ r: 3, fill: '#10b981' }} />
              <Area type="monotone" dataKey="cashFlow" stroke="#f59e0b" fill="url(#cashFlowGrad)" strokeWidth={2} dot={{ r: 3, fill: '#f59e0b' }} />
              <Line type="monotone" dataKey="total" stroke="#a78bfa" strokeWidth={2} strokeDasharray="6 3" dot={{ r: 4, fill: '#a78bfa' }} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Investment Scoring Cards */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
          <Star className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-medium text-gray-400">Investment Scoring</h3>
        </div>
        <div className="grid grid-cols-2 gap-0 divide-x divide-gray-800/50">
          {scoredProperties.map((prop) => (
            <div key={prop.address} className="p-5 hover:bg-gray-800/30 border-b border-gray-800/50">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="text-sm font-medium text-cyan-400">{prop.address}</div>
                  <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border mt-1 ${recommendationColors[prop.recommendation]}`}>
                    {prop.recommendation}
                  </span>
                </div>
                <div className={`w-14 h-14 rounded-xl flex items-center justify-center text-lg font-bold ${getScoreColor(prop.overallScore)} ${getScoreBg(prop.overallScore)}`}>
                  {prop.overallScore}
                </div>
              </div>
              <div className="space-y-2">
                <ScoreBar label="Cash Flow" score={prop.cashFlowScore} />
                <ScoreBar label="Appreciation" score={prop.appreciationScore} />
                <ScoreBar label="Risk" score={prop.riskScore} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function ScoreBar({ label, score }: { label: string; score: number }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-gray-500 w-20">{label}</span>
      <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${score >= 90 ? 'bg-green-500' : score >= 80 ? 'bg-cyan-500' : score >= 70 ? 'bg-yellow-500' : 'bg-red-500'}`}
          style={{ width: `${score}%` }}
        />
      </div>
      <span className={`text-xs font-medium w-8 text-right ${getScoreColor(score)}`}>{score}</span>
    </div>
  )
}

function KpiCard({ title, value, icon: Icon, detail, positive, highlight }: {
  title: string; value: string; icon: React.ElementType; detail: string; positive?: boolean; highlight?: boolean
}) {
  return (
    <div className={`bg-gray-900 rounded-xl p-5 border ${highlight ? 'border-cyan-800/50' : 'border-gray-800'}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className="w-5 h-5 text-gray-500" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className={`text-sm mt-1 ${positive ? 'text-green-400' : 'text-gray-400'}`}>{detail}</div>
    </div>
  )
}
