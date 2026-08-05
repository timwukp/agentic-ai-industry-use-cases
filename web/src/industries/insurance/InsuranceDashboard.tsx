import { useState } from 'react'
import {
  AlertTriangle,
  BadgeDollarSign,
  Clock,
  ShieldAlert,
  Timer,
  Zap,
} from 'lucide-react'
import { useApi } from '../../lib/api'
import { Card, ErrorPane, LoadingPane, SimulatedBadge, StatCard } from '../finance/widgets'
import {
  AskAgentButton,
  DataTable,
  MeterBar,
  RankedBars,
  SectionHeader,
  StatusPill,
  deltaClass,
  fmtCompactUsd,
  fmtNum,
  fmtPct,
  fmtSignedPct,
  fmtUsd0,
  type Column,
} from '../common/widgets'
import type {
  ClaimRow,
  ClaimStatusFilter,
  ClaimsResponse,
  OverviewResponse,
} from './types'
import { CLAIM_STATUS_FILTERS } from './types'

const ACCENT = 'text-indigo-400'
const SERIES = '#818cf8' // indigo-400
const HOVER = 'hover:text-indigo-300'

/** Above this modeled fraud score a claim goes to an investigator. */
const FRAUD_REVIEW_THRESHOLD = 0.7

function riskTone(score: number) {
  if (score >= FRAUD_REVIEW_THRESHOLD) return { tone: 'red' as const, label: 'REVIEW' }
  if (score >= 0.4) return { tone: 'amber' as const, label: 'WATCH' }
  return { tone: 'slate' as const, label: 'CLEAR' }
}

function STATUS_TONE(status: string) {
  const s = status.toUpperCase()
  if (s === 'INVESTIGATION') return 'red' as const
  if (s === 'UNDER_REVIEW' || s === 'PENDING') return 'amber' as const
  if (s === 'CLOSED' || s === 'SETTLED' || s === 'APPROVED') return 'green' as const
  return 'slate' as const
}

export default function InsuranceDashboard() {
  const [statusFilter, setStatusFilter] = useState<ClaimStatusFilter>('all')

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-4 lg:p-6 space-y-6 @container">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg lg:text-xl font-bold text-white">Insurance Claims</h2>
          <SimulatedBadge />
        </div>

        <BookSection />
        <QueueSection statusFilter={statusFilter} onFilterChange={setStatusFilter} />
      </div>
    </div>
  )
}

/* ------------------------------- book of business -------------------------- */

function BookSection() {
  const { data, loading, error, reload } = useApi<OverviewResponse>(
    '/api/insurance/overview',
  )

  if (loading) return <LoadingPane label="Loading claims book…" />
  if (error || !data || data.error) {
    return (
      <Card title="Claims Book">
        <ErrorPane message={error ?? data?.error ?? 'No overview data'} onRetry={reload} />
      </Card>
    )
  }

  const fraud = data.fraud ?? {}
  const fm = fraud.metrics ?? {}
  const settlement = data.settlement ?? {}
  const kpis = settlement.kpis ?? {}
  const trend = settlement.trend ?? {}

  const fraudTypes = (fraud.top_fraud_types ?? []).map((t) => ({
    type: t.type ?? '—',
    count: t.count ?? 0,
    pct: t.pct ?? 0,
  }))

  const byType = Object.entries(settlement.by_claim_type ?? {}).map(
    ([type, entry]) => ({
      type,
      count: entry.count ?? 0,
      avg: entry.avg_amount ?? 0,
    }),
  )
  const maxAvg = Math.max(...byType.map((r) => r.avg), 1)

  const fpRate = fm.false_positive_rate_pct ?? 0

  return (
    <section className="space-y-4 @container">
      <SectionHeader
        title="Claims Book"
        accentClass={ACCENT}
        action={
          <AskAgentButton
            hoverClass={HOVER}
            prompt="Summarize our current fraud detection performance and settlement KPIs, and flag the two metrics most worth attention this month."
          />
        }
      />

      <div className="grid grid-cols-2 @xl:grid-cols-4 gap-3 @lg:gap-4">
        <StatCard
          title="Claims Screened"
          value={fmtNum(fm.total_claims_screened)}
          icon={ShieldAlert}
          sub={`${fmtNum(fm.flagged_for_review)} flagged for review`}
        />
        <StatCard
          title="Fraud Detection Rate"
          value={fmtPct(fm.detection_rate_pct)}
          icon={Zap}
          sub={`${fmtPct(fpRate)} false positives`}
          subClass={fpRate > 5 ? 'text-amber-400' : 'text-slate-400'}
        />
        <StatCard
          title="Detection Savings"
          value={fmtCompactUsd(fm.savings_from_detection)}
          icon={BadgeDollarSign}
          sub={`${fmtNum(fm.confirmed_fraud)} confirmed cases`}
        />
        <StatCard
          title="Avg Processing"
          value={
            kpis.avg_processing_days != null ? `${kpis.avg_processing_days}d` : '—'
          }
          icon={Timer}
          sub={
            trend.processing_time_vs_prior_month != null
              ? `${fmtSignedPct(trend.processing_time_vs_prior_month)} vs prior month`
              : undefined
          }
          subClass={
            trend.processing_time_vs_prior_month != null
              ? deltaClass(trend.processing_time_vs_prior_month, true)
              : 'text-slate-400'
          }
        />
      </div>

      <div className="grid grid-cols-1 @3xl:grid-cols-2 gap-3 @lg:gap-4">
        <Card title="Top Fraud Patterns (confirmed cases)">
          <div className="p-4 @lg:p-5">
            {fraudTypes.length === 0 ? (
              <p className="py-6 text-center text-sm text-slate-500">
                No fraud patterns
              </p>
            ) : (
              <RankedBars
                data={fraudTypes}
                categoryKey="type"
                valueKey="count"
                color={SERIES}
                labelWidth={150}
                valueFormatter={(v) => fmtNum(v)}
              />
            )}
          </div>
        </Card>

        <Card
          title="Settlement Mix by Claim Type"
          action={
            <span className="text-[11px] text-slate-500 tabular-nums">
              {fmtNum(kpis.total_settlements)} settlements ·{' '}
              {fmtCompactUsd(kpis.total_amount_paid)} paid
            </span>
          }
        >
          {byType.length === 0 ? (
            <p className="py-6 text-center text-sm text-slate-500">
              No settlement data
            </p>
          ) : (
            <ul className="p-4 @lg:p-5 space-y-3">
              {byType.map((row) => (
                <li key={row.type}>
                  <div className="flex items-baseline justify-between gap-2 mb-1.5">
                    <span className="text-sm text-white capitalize">{row.type}</span>
                    <span className="text-xs text-slate-400 tabular-nums">
                      {fmtNum(row.count)} claims · avg {fmtUsd0(row.avg)}
                    </span>
                  </div>
                  <MeterBar
                    pct={(row.avg / maxAvg) * 100}
                    fillClass="bg-indigo-500"
                  />
                </li>
              ))}
              <li className="pt-2 flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-slate-500 tabular-nums border-t border-slate-800">
                <span>
                  straight-through {fmtPct(kpis.straight_through_rate_pct)}
                </span>
                <span>median {fmtUsd0(kpis.median_settlement)}</span>
                <span>CSAT {kpis.customer_satisfaction ?? '—'}/5</span>
              </li>
            </ul>
          )}
        </Card>
      </div>
    </section>
  )
}

/* --------------------------------- claim queue ---------------------------- */

function QueueSection({
  statusFilter,
  onFilterChange,
}: {
  statusFilter: ClaimStatusFilter
  onFilterChange: (value: ClaimStatusFilter) => void
}) {
  const { data, loading, error, reload } = useApi<ClaimsResponse>(
    `/api/insurance/claims?status=${statusFilter}&days=30`,
  )

  const summary = data?.summary ?? {}

  const columns: Array<Column<ClaimRow>> = [
    {
      header: 'Claim',
      render: (row) => (
        <span className="font-mono text-xs text-white">{row.claim_id ?? '—'}</span>
      ),
    },
    {
      header: 'Type',
      render: (row) => <span className="capitalize">{row.claim_type ?? '—'}</span>,
    },
    {
      header: 'Filed',
      render: (row) => (
        <span className="tabular-nums text-slate-400">{row.filed_date ?? '—'}</span>
      ),
    },
    {
      header: 'Status',
      render: (row) => (
        <StatusPill
          tone={STATUS_TONE(row.status ?? '')}
          label={(row.status ?? '—').replace(/_/g, ' ')}
        />
      ),
    },
    {
      header: 'Priority',
      render: (row) => (
        <StatusPill
          tone={(row.priority ?? '').toUpperCase() === 'HIGH' ? 'amber' : 'slate'}
          label={row.priority ?? '—'}
        />
      ),
    },
    {
      header: 'Fraud score',
      numeric: true,
      render: (row) => {
        const score = row.fraud_risk ?? 0
        const { tone, label } = riskTone(score)
        return (
          <span className="inline-flex items-center gap-2 justify-end">
            <span className="tabular-nums text-white">{score.toFixed(2)}</span>
            <StatusPill tone={tone} label={label} />
          </span>
        )
      },
    },
    {
      header: 'Amount',
      numeric: true,
      className: 'text-white',
      render: (row) => fmtUsd0(row.amount),
    },
  ]

  return (
    <section className="space-y-4 @container">
      <SectionHeader
        title="Claim Queue"
        accentClass={ACCENT}
        action={
          <AskAgentButton
            hoverClass={HOVER}
            prompt={`Review the ${statusFilter} claims from the last 30 days, rank the highest-risk ones, and draft next actions for the top three.`}
          />
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        {CLAIM_STATUS_FILTERS.map((value) => (
          <button
            key={value}
            type="button"
            onClick={() => onFilterChange(value)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border capitalize transition-colors ${
              statusFilter === value
                ? 'bg-indigo-600 border-indigo-500 text-white'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
            }`}
          >
            {value}
          </button>
        ))}
      </div>

      {loading ? (
        <LoadingPane label="Loading claim queue…" />
      ) : error || !data || data.error ? (
        <Card title="Claim Queue">
          <ErrorPane message={error ?? data?.error ?? 'No claims'} onRetry={reload} />
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-2 @xl:grid-cols-4 gap-3 @lg:gap-4">
            <StatCard
              title="Open Claims"
              value={fmtNum(data.open_claims)}
              icon={Clock}
              sub={`of ${fmtNum(data.total_claims)} filed in 30 days`}
            />
            <StatCard
              title="Reserve Exposure"
              value={fmtCompactUsd(summary.reserve_exposure)}
              icon={BadgeDollarSign}
              sub={`avg ${fmtUsd0(summary.avg_open_amount)} per open claim`}
            />
            <StatCard
              title="High Priority"
              value={fmtNum(summary.high_priority)}
              icon={AlertTriangle}
              sub="need adjuster today"
              subClass={
                (summary.high_priority ?? 0) > 0 ? 'text-amber-400' : 'text-slate-400'
              }
            />
            <StatCard
              title="Fraud Flagged"
              value={fmtNum(summary.flagged_fraud)}
              icon={ShieldAlert}
              sub={`score > ${FRAUD_REVIEW_THRESHOLD}`}
              subClass={
                (summary.flagged_fraud ?? 0) > 0 ? 'text-red-400' : 'text-slate-400'
              }
            />
          </div>

          <Card title={`Claims — ${statusFilter}`}>
            <DataTable
              columns={columns}
              rows={data.claims ?? []}
              rowKey={(row, i) => row.claim_id ?? String(i)}
              empty="No claims match this filter"
              maxHeight="max-h-96"
            />
          </Card>
        </>
      )}
    </section>
  )
}
