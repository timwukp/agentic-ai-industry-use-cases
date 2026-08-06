import { useState } from 'react'
import { useApi } from '../../../lib/api'
import { useLocale } from '../../../i18n/LocaleContext'
import { Card, ErrorPane, LoadingPane } from '../../finance/widgets'
import { StatusPill, type PillTone } from '../widgets'
import type { LabsResponse } from '../types'
import { parsePct } from '../types'

type Tab = 'labs' | 'meds'

type TFn = (key: string, params?: Record<string, string | number>) => string

function flagTone(
  t: TFn,
  flag?: string | null,
): { tone: PillTone; label: string } | null {
  if (!flag) return null
  const f = flag.toUpperCase()
  if (f === 'HIGH') return { tone: 'red', label: t('healthcare.pillHigh') }
  if (f === 'LOW') return { tone: 'sky', label: t('healthcare.pillLow') }
  if (f === 'BORDERLINE') return { tone: 'amber', label: t('healthcare.pillBorderline') }
  return { tone: 'slate', label: f }
}

export default function LabsMedsCard({ patientId }: { patientId: string }) {
  const { t } = useLocale()
  const [tab, setTab] = useState<Tab>('labs')
  const { data, loading, error, reload } = useApi<LabsResponse>(
    `/api/healthcare/labs?patientId=${encodeURIComponent(patientId)}&days=90`,
  )

  const tabs = (
    <div className="flex rounded-lg border border-slate-700 overflow-hidden text-xs">
      {(
        [
          ['labs', t('healthcare.tabLabs')],
          ['meds', t('healthcare.tabMedications')],
        ] as Array<[Tab, string]>
      ).map(([id, label]) => (
        <button
          key={id}
          type="button"
          onClick={() => setTab(id)}
          className={`px-3 py-1.5 transition-colors ${
            tab === id
              ? 'bg-slate-700 text-white'
              : 'bg-slate-800/60 text-slate-400 hover:text-slate-200'
          }`}
        >
          {label}
        </button>
      ))}
    </div>
  )

  return (
    <Card title={t('healthcare.labsMeds')} action={tabs}>
      {loading ? (
        <LoadingPane label={t('healthcare.loadingLabs')} />
      ) : error || !data || data.error ? (
        <ErrorPane
          message={error ?? data?.error ?? t('healthcare.noLabsData')}
          onRetry={reload}
        />
      ) : tab === 'labs' ? (
        <LabsTab data={data} />
      ) : (
        <MedsTab data={data} />
      )}
    </Card>
  )
}

function LabsTab({ data }: { data: LabsResponse }) {
  const { t } = useLocale()
  const panels = data.labs?.results ?? []
  const critical = data.labs?.summary?.critical_flags

  return (
    <div className="p-4 @lg:p-5 space-y-4">
      {critical && critical.length > 0 && (
        <div className="px-3 py-2.5 rounded-lg bg-red-950/50 border border-red-900 text-xs text-red-200">
          <span className="font-semibold">
            {t('healthcare.criticalBanner', { list: critical.join(', ') })}
          </span>{' '}
          {data.labs?.recommendation}
        </div>
      )}
      {panels.length === 0 ? (
        <p className="py-4 text-center text-sm text-slate-500">
          {t('healthcare.noLabResults', { n: data.labs?.lookback_days ?? 90 })}
        </p>
      ) : (
        panels.map((panel, pi) => (
          <div key={`${panel.order_id ?? pi}`}>
            <div className="flex flex-wrap items-baseline gap-x-2 mb-1.5">
              <span className="text-sm font-medium text-white">
                {panel.panel_name ?? t('healthcare.panelFallback')}
              </span>
              <span className="text-[11px] text-slate-500 tabular-nums">
                {panel.collection_date ?? ''}
              </span>
              {panel.ordering_provider && (
                <span className="text-[11px] text-slate-500">
                  · {panel.ordering_provider}
                </span>
              )}
            </div>
            <table className="w-full text-xs">
              <tbody className="divide-y divide-slate-800/70">
                {(panel.tests ?? []).map((test, ti) => {
                  const flag = flagTone(t, test.flag)
                  return (
                    <tr key={`${test.test ?? ti}`}>
                      <td className="py-1.5 pr-2 text-slate-300">{test.test ?? '—'}</td>
                      <td className="py-1.5 pr-2 text-white tabular-nums whitespace-nowrap">
                        {test.value ?? '—'}
                        {test.unit ? ` ${test.unit}` : ''}
                      </td>
                      <td className="py-1.5 pr-2 text-slate-500 tabular-nums whitespace-nowrap">
                        {test.ref_range ?? ''}
                      </td>
                      <td className="py-1.5 text-right">
                        {flag && <StatusPill tone={flag.tone} label={flag.label} />}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ))
      )}
    </div>
  )
}

function MedsTab({ data }: { data: LabsResponse }) {
  const { t } = useLocale()
  const meds = data.medications?.medications ?? []
  const alerts = data.medications?.alerts ?? []

  return (
    <div className="p-4 @lg:p-5 space-y-4">
      {alerts.map((alert, i) => (
        <div
          key={`${alert.type ?? i}`}
          className="px-3 py-2.5 rounded-lg bg-amber-950/40 border border-amber-900/50 text-xs text-amber-200"
        >
          <span className="font-semibold">
            {alert.type ?? t('healthcare.alertFallback')}:
          </span>{' '}
          {alert.message ?? ''}
        </div>
      ))}
      {meds.length === 0 ? (
        <p className="py-4 text-center text-sm text-slate-500">
          {t('healthcare.noMedications')}
        </p>
      ) : (
        <ul className="divide-y divide-slate-800/70">
          {meds.map((med, i) => {
            const adherence = parsePct(med.adherence_rate)
            const lowAdherence = adherence !== null && adherence < 85
            return (
              <li
                key={`${med.name ?? i}`}
                className="py-2 flex flex-wrap items-center gap-x-3 gap-y-1"
              >
                <div className="flex-1 min-w-[160px]">
                  <span className="text-sm text-white">{med.name ?? '—'}</span>
                  <span className="text-xs text-slate-400 ml-2">
                    {[med.dosage, med.frequency].filter(Boolean).join(' · ')}
                  </span>
                </div>
                <span
                  className={`text-xs tabular-nums ${lowAdherence ? 'text-amber-400' : 'text-slate-400'}`}
                  title={t('healthcare.adherenceRate')}
                >
                  {t('healthcare.adherenceSuffix', { rate: med.adherence_rate ?? '—' })}
                </span>
                {med.refill_alert && (
                  <StatusPill tone="amber" label={t('healthcare.pillRefill')} />
                )}
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
