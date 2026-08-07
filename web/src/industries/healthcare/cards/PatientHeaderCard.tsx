import { Card } from '../../finance/widgets'
import { useLocale } from '../../../i18n/LocaleContext'
import { StatusPill, type PillTone } from '../widgets'
import type { PatientSummary } from '../types'

function allergyTone(severity?: string): PillTone {
  const s = (severity ?? '').toLowerCase()
  if (s === 'severe') return 'red'
  if (s === 'moderate') return 'amber'
  return 'slate'
}

export default function PatientHeaderCard({ summary }: { summary?: PatientSummary }) {
  const { t } = useLocale()
  const demo = summary?.demographics
  const allergies = summary?.allergies ?? []
  const conditions = (summary?.active_conditions ?? []).filter(
    (c) => (c.status ?? 'active') === 'active',
  )
  const vitals = summary?.vitals_last_recorded

  if (!summary) {
    return (
      <Card>
        <p className="p-5 text-sm text-slate-500">{t('healthcare.noPatientSummary')}</p>
      </Card>
    )
  }

  const identity = [
    demo?.age != null || demo?.sex ? [demo?.age, demo?.sex].filter((v) => v != null).join(' / ') : null,
    demo?.insurance,
    demo?.primary_care_provider
      ? t('healthcare.pcp', { name: demo.primary_care_provider })
      : null,
  ].filter(Boolean)

  const vitalBits = vitals
    ? [
        vitals.date ? t('healthcare.lastVitals', { date: vitals.date }) : null,
        vitals.blood_pressure ? `BP ${vitals.blood_pressure}` : null,
        vitals.heart_rate ? `HR ${vitals.heart_rate}` : null,
        vitals.oxygen_saturation ? `SpO2 ${vitals.oxygen_saturation}` : null,
        vitals.bmi != null ? `BMI ${vitals.bmi}` : null,
      ].filter(Boolean)
    : []

  return (
    <Card>
      <div className="p-4 @lg:p-5 space-y-3">
        {/* Identity line */}
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <span className="text-lg font-bold text-white">
            {demo?.name ?? summary.patient_id ?? t('healthcare.unknownPatient')}
          </span>
          <span className="text-sm text-slate-400">{identity.join(' · ')}</span>
        </div>

        {/* Allergy + condition chips */}
        {(allergies.length > 0 || conditions.length > 0) && (
          <div className="flex flex-wrap items-center gap-1.5">
            {allergies.map((a, i) => (
              <span key={`allergy-${a.allergen ?? i}`} title={a.reaction}>
                <StatusPill
                  tone={allergyTone(a.severity)}
                  label={`⚠ ${a.allergen ?? t('healthcare.allergyFallback')}`}
                />
              </span>
            ))}
            {conditions.map((c, i) => (
              <span
                key={`cond-${c.code ?? i}`}
                title={c.description}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] border bg-slate-800/70 border-slate-700 text-slate-300 max-w-[220px]"
              >
                <span className="tabular-nums text-slate-400">{c.code ?? '—'}</span>
                <span className="truncate">{c.description ?? ''}</span>
              </span>
            ))}
          </div>
        )}

        {/* Last vitals one-liner */}
        {vitalBits.length > 0 && (
          <div className="text-xs text-slate-400 tabular-nums">
            {vitalBits.join(' · ')}
          </div>
        )}
      </div>
    </Card>
  )
}
