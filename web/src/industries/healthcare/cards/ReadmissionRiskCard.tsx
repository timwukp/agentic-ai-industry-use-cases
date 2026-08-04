import { useState } from 'react'
import { BookOpen, Car, ChevronDown, Home, Utensils, type LucideIcon } from 'lucide-react'
import { Card } from '../../finance/widgets'
import { AskAgentButton, PriorityPill, StatusPill, type PillTone } from '../widgets'
import type { ReadmissionRisk } from '../types'

/** Readmission model scores range 5–55; ticks at the 15 / 30 level cutoffs. */
const SCALE_MIN = 5
const SCALE_MAX = 55
const TICKS = [15, 30]

const LEVEL_STYLES: Record<string, { tone: PillTone; bar: string; text: string }> = {
  LOW: { tone: 'green', bar: 'bg-green-500', text: 'text-green-400' },
  MODERATE: { tone: 'amber', bar: 'bg-amber-500', text: 'text-amber-400' },
  HIGH: { tone: 'red', bar: 'bg-red-500', text: 'text-red-400' },
}

function pctOfScale(score: number): number {
  return Math.min(Math.max(((score - SCALE_MIN) / (SCALE_MAX - SCALE_MIN)) * 100, 0), 100)
}

const SDOH_ROWS: Array<{
  icon: LucideIcon
  label: string
  active: (s: NonNullable<ReadmissionRisk['social_determinants']>) => boolean
}> = [
  { icon: Home, label: 'Lives alone', active: (s) => s.lives_alone === true },
  {
    icon: Car,
    label: 'Transportation barriers',
    active: (s) => s.transportation_barriers === true,
  },
  { icon: Utensils, label: 'Food insecurity', active: (s) => s.food_insecurity === true },
  {
    icon: BookOpen,
    label: 'Limited health literacy',
    active: (s) => (s.health_literacy ?? '').toLowerCase() === 'limited',
  },
]

export default function ReadmissionRiskCard({
  risk,
  patientId,
}: {
  risk?: ReadmissionRisk
  patientId: string
}) {
  const [showAllInterventions, setShowAllInterventions] = useState(false)

  const level = (risk?.risk_level ?? '').toUpperCase()
  const style = LEVEL_STYLES[level] ?? LEVEL_STYLES.MODERATE
  const score = risk?.risk_score
  const social = risk?.social_determinants
  const sdohRows = social ? SDOH_ROWS.filter((row) => row.active(social)) : []
  const interventions = risk?.recommended_interventions ?? []
  const visibleInterventions = showAllInterventions
    ? interventions
    : interventions.slice(0, 3)
  const hiddenCount = interventions.length - 3
  const factors = risk?.contributing_factors ?? []

  return (
    <Card
      title="30-Day Readmission Risk"
      action={
        <AskAgentButton
          prompt={`Summarize readmission risk for ${patientId} and draft the intervention plan`}
        />
      }
    >
      {!risk ? (
        <p className="p-5 text-sm text-slate-500">No readmission risk data.</p>
      ) : (
        <div className="p-4 @lg:p-5 space-y-4">
          {/* Hero score */}
          <div className="flex items-center justify-between gap-3">
            <span className={`text-4xl font-bold tabular-nums ${style.text}`}>
              {score != null ? score : '—'}
            </span>
            <StatusPill tone={style.tone} label={`${level || 'UNKNOWN'} RISK`} />
          </div>

          {/* Meter (scaled 5–55, ticks at 15 and 30) */}
          <div>
            <div className="relative h-2 bg-slate-800 rounded-full">
              <div
                className={`absolute inset-y-0 left-0 rounded-full ${style.bar}`}
                style={{ width: `${pctOfScale(score ?? SCALE_MIN)}%` }}
              />
              {TICKS.map((t) => (
                <div
                  key={t}
                  className="absolute top-0 h-full w-0.5 bg-slate-600"
                  style={{ left: `${pctOfScale(t)}%` }}
                  title={`${t}`}
                />
              ))}
            </div>
            <div className="flex justify-between text-[11px] text-slate-500 mt-1 tabular-nums">
              <span>{SCALE_MIN}</span>
              <span>15</span>
              <span>30</span>
              <span>{SCALE_MAX}</span>
            </div>
          </div>

          <div className="text-xs text-slate-400 tabular-nums">
            30-day probability: {risk.probability_30day_readmission ?? '—'}
            <span className="text-slate-500">
              {' '}
              · natl avg {risk.benchmark?.national_avg_readmission_rate ?? '15.6%'}
            </span>
          </div>

          {/* SDOH flags (only true/limited) */}
          {sdohRows.length > 0 && (
            <div className="space-y-1.5">
              <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
                Social determinants
              </div>
              {sdohRows.map(({ icon: Icon, label }) => (
                <div key={label} className="flex items-center gap-2 text-xs text-slate-300">
                  <Icon className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                  {label}
                </div>
              ))}
            </div>
          )}

          {/* Recommended interventions (top 3 + toggle) */}
          {interventions.length > 0 && (
            <div className="space-y-1.5">
              <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
                Recommended interventions
              </div>
              <ul className="space-y-1.5">
                {visibleInterventions.map((iv, i) => (
                  <li
                    key={`${iv.intervention ?? 'iv'}-${i}`}
                    className="flex items-start gap-2"
                  >
                    <PriorityPill priority={iv.priority} />
                    <span className="text-xs text-slate-300 pt-0.5">
                      {iv.intervention ?? '—'}
                    </span>
                  </li>
                ))}
              </ul>
              {hiddenCount > 0 && (
                <button
                  type="button"
                  onClick={() => setShowAllInterventions((v) => !v)}
                  className="text-xs text-rose-300 hover:text-rose-200 transition-colors"
                >
                  {showAllInterventions ? 'Show fewer' : `+${hiddenCount} more`}
                </button>
              )}
            </div>
          )}

          {/* Contributing factors (collapsed) */}
          {factors.length > 0 && (
            <details className="group">
              <summary className="flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer select-none hover:text-slate-300 list-none">
                <ChevronDown className="w-3.5 h-3.5 transition-transform group-open:rotate-180" />
                Contributing factors ({factors.length})
              </summary>
              <ul className="mt-2 space-y-1 pl-5">
                {factors.map((factor) => (
                  <li key={factor} className="flex gap-2 text-xs text-slate-400">
                    <span className="text-slate-600 shrink-0">–</span>
                    {factor}
                  </li>
                ))}
              </ul>
            </details>
          )}

          {risk.risk_model && (
            <p className="text-[11px] text-slate-600">{risk.risk_model}</p>
          )}
        </div>
      )}
    </Card>
  )
}
