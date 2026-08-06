import { useState } from 'react'
import { MapPin, Video } from 'lucide-react'
import { useApi } from '../../lib/api'
import { useLocale } from '../../i18n/LocaleContext'
import { Card, ErrorPane, LoadingPane } from '../finance/widgets'
import { AskAgentButton, SectionHeader } from './widgets'
import type { AvailabilityResponse } from './types'

/** Mirrors PROVIDER_DIRECTORY in tools/healthcare/scheduling/handler.py. */
const PROVIDERS = [
  { id: 'DR-CHEN', label: 'Dr. Sarah Chen — Internal Medicine' },
  { id: 'DR-PATEL', label: 'Dr. Priya Patel — Pulmonology' },
  { id: 'DR-WILSON', label: 'Dr. James Wilson — Gastroenterology' },
  { id: 'DR-KIM', label: 'Dr. Lisa Kim — Psychiatry' },
  { id: 'DR-GARCIA', label: 'Dr. Carlos Garcia — Cardiology' },
  { id: 'NP-RODRIGUEZ', label: 'Maria Rodriguez, NP — Primary Care' },
]

export default function SchedulingSection({ patientId }: { patientId: string }) {
  const { t } = useLocale()
  const [providerId, setProviderId] = useState(PROVIDERS[0].id)
  const { data, loading, error, reload } = useApi<AvailabilityResponse>(
    `/api/healthcare/availability?providerId=${encodeURIComponent(providerId)}&days=5`,
  )

  const headerAction = (
    <div className="flex items-center gap-1">
      <AskAgentButton
        prompt={`Book a follow-up for ${patientId} with ${providerId} at the earliest available slot`}
      />
      <select
        value={providerId}
        onChange={(e) => setProviderId(e.target.value)}
        aria-label={t('healthcare.providerLabel')}
        className="max-w-[240px] px-2.5 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none focus:border-rose-500/60"
      >
        {PROVIDERS.map((p) => (
          <option key={p.id} value={p.id}>
            {p.label}
          </option>
        ))}
      </select>
    </div>
  )

  const provider = data?.provider
  const days = data?.availability ?? []
  const title = provider?.name
    ? `${provider.name} — ${provider.specialty ?? ''}`.replace(/ — $/, '')
    : t('healthcare.providerAvailability')

  return (
    <section className="space-y-4 @container">
      <SectionHeader title={t('healthcare.scheduling')} />
      <Card title={title} action={headerAction}>
        {loading ? (
          <LoadingPane label={t('healthcare.loadingAvailability')} />
        ) : error || !data || data.error ? (
          <ErrorPane
            message={error ?? data?.error ?? t('healthcare.noAvailabilityData')}
            onRetry={reload}
          />
        ) : (
          <div className="p-4 @lg:p-5 space-y-4">
            {provider?.location && (
              <div className="flex items-center gap-1.5 text-xs text-slate-500">
                <MapPin className="w-3.5 h-3.5" />
                {provider.location}
                {data.date_range?.start && data.date_range?.end && (
                  <span className="ml-2">
                    {data.date_range.start} → {data.date_range.end}
                  </span>
                )}
              </div>
            )}

            {days.length === 0 ? (
              <p className="py-6 text-center text-sm text-slate-500">
                {data.summary?.message ?? t('healthcare.noSlotsRange')}
              </p>
            ) : (
              <div className="grid grid-cols-1 @xl:grid-cols-2 @4xl:grid-cols-5 gap-3">
                {days.map((day) => (
                  <div
                    key={day.date}
                    className="rounded-lg border border-slate-800 bg-slate-950/40 p-3"
                  >
                    <div className="mb-2.5">
                      <div className="text-sm font-medium text-white">
                        {day.day_of_week ?? '—'}
                      </div>
                      <div className="text-[11px] text-slate-500 tabular-nums">
                        {day.date}
                      </div>
                    </div>
                    <div className="flex flex-wrap @4xl:flex-col gap-1.5">
                      {(day.available_slots ?? []).map((slot) => {
                        const telehealth = slot.slot_type === 'telehealth'
                        return (
                          <span
                            key={`${day.date}-${slot.time}`}
                            title={t('healthcare.slotTooltip', {
                              min: slot.duration_minutes ?? '?',
                              type: telehealth
                                ? t('healthcare.telehealthSlot')
                                : t('healthcare.inPerson'),
                            })}
                            className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[11px] border tabular-nums ${
                              telehealth
                                ? 'bg-sky-950/50 border-sky-800/50 text-sky-300'
                                : 'bg-slate-800/70 border-slate-700 text-slate-200'
                            }`}
                          >
                            {telehealth ? (
                              <Video className="w-3 h-3" />
                            ) : (
                              <MapPin className="w-3 h-3" />
                            )}
                            {slot.time ?? '—'}
                          </span>
                        )
                      })}
                      {(day.available_slots ?? []).length === 0 && (
                        <span className="text-[11px] text-slate-600">
                          {t('healthcare.noSlots')}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="flex items-center gap-4 text-[11px] text-slate-500">
              <span className="inline-flex items-center gap-1.5">
                <MapPin className="w-3 h-3" /> {t('healthcare.inPerson')}
              </span>
              <span className="inline-flex items-center gap-1.5">
                <Video className="w-3 h-3 text-sky-400" /> {t('healthcare.telehealthSlot')}
              </span>
              {data.summary?.total_available_slots != null && (
                <span className="ml-auto tabular-nums">
                  {t('healthcare.openSlots', { n: data.summary.total_available_slots })}
                </span>
              )}
            </div>
          </div>
        )}
      </Card>
    </section>
  )
}
