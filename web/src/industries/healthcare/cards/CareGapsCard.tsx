import { Card } from '../../finance/widgets'
import { AskAgentButton, PriorityPill, StatusPill, type PillTone } from '../widgets'
import type { CareGapAnalysis } from '../types'

function gapTone(status?: string): { tone: PillTone; label: string } {
  const s = (status ?? '').toUpperCase()
  if (s === 'OVERDUE') return { tone: 'red', label: 'OVERDUE' }
  if (s === 'DUE SOON') return { tone: 'amber', label: 'DUE SOON' }
  if (s === 'NEVER COMPLETED') return { tone: 'violet', label: 'NEVER COMPLETED' }
  return { tone: 'slate', label: s || '—' }
}

export default function CareGapsCard({
  careGaps,
  patientId,
}: {
  careGaps?: CareGapAnalysis
  patientId: string
}) {
  const gaps = careGaps?.care_gaps ?? []
  const total = careGaps?.total_care_gaps ?? gaps.length
  const high =
    careGaps?.high_priority_gaps ??
    gaps.filter((g) => (g.priority ?? '').toUpperCase() === 'HIGH').length
  const impactMsg = careGaps?.quality_impact?.message

  return (
    <Card
      title={`Care Gaps (${total}) · ${high} high priority`}
      action={
        <AskAgentButton
          prompt={`Create an outreach plan to close the care gaps for ${patientId}`}
        />
      }
    >
      {gaps.length === 0 ? (
        <p className="p-5 text-sm text-slate-500">No open care gaps.</p>
      ) : (
        <ul className="p-2 @lg:p-3 divide-y divide-slate-800/70">
          {gaps.map((gap, i) => {
            const status = gapTone(gap.status)
            return (
              <li
                key={`${gap.measure ?? 'gap'}-${i}`}
                className="px-2 py-2.5 flex flex-wrap items-center gap-x-3 gap-y-1.5"
              >
                <PriorityPill priority={gap.priority} />
                <span className="text-sm text-white flex-1 min-w-[140px]" title={gap.description}>
                  {gap.measure ?? '—'}
                </span>
                <StatusPill tone={status.tone} label={status.label} />
                <span className="text-xs text-slate-400 tabular-nums">
                  {gap.due_date ?? ''}
                </span>
                {gap.quality_measure && (
                  <span className="text-[11px] text-slate-500 basis-full pl-[calc(0.75rem+2ch)] @lg:basis-auto @lg:pl-0">
                    {gap.quality_measure}
                  </span>
                )}
              </li>
            )
          })}
        </ul>
      )}
      {impactMsg && (
        <div className="mx-4 mb-4 px-3 py-2.5 rounded-lg bg-rose-950/40 border border-rose-900/50 text-xs text-rose-200">
          {impactMsg}
        </div>
      )}
    </Card>
  )
}
