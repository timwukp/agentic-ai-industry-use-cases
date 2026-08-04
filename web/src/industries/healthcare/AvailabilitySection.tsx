import { useState } from 'react'
import { MapPin, Video } from 'lucide-react'
import { useApi } from '../../lib/api'
import { Card, ErrorPane, LoadingPane } from '../finance/widgets'
import type { AvailabilityResponse } from './types'

const PROVIDERS = [
  { id: 'DR-SMITH', label: 'Dr. Smith' },
  { id: 'DR-JONES', label: 'Dr. Jones' },
  { id: 'DR-PATEL', label: 'Dr. Patel' },
]

export default function AvailabilitySection() {
  const [providerId, setProviderId] = useState(PROVIDERS[0].id)
  const { data, loading, error, reload } = useApi<AvailabilityResponse>(
    `/api/healthcare/availability?providerId=${encodeURIComponent(providerId)}&days=5`,
  )

  const providerSelect = (
    <select
      value={providerId}
      onChange={(e) => setProviderId(e.target.value)}
      aria-label="Provider"
      className="px-2.5 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none focus:border-rose-500/60"
    >
      {PROVIDERS.map((p) => (
        <option key={p.id} value={p.id}>
          {p.label}
        </option>
      ))}
    </select>
  )

  const provider = data?.provider
  const days = data?.availability ?? []
  const title = provider?.name
    ? `${provider.name} — ${provider.specialty ?? ''}`.replace(/ — $/, '')
    : 'Provider Availability'

  return (
    <section className="space-y-4 @container">
      <h3 className="text-sm font-semibold uppercase tracking-wider text-rose-400">
        Provider Availability
      </h3>
      <Card title={title} action={providerSelect}>
        {loading ? (
          <LoadingPane label="Loading availability…" />
        ) : error || !data || data.error ? (
          <ErrorPane
            message={error ?? data?.error ?? 'No availability data'}
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
                {data.summary?.message ?? 'No available slots in this date range.'}
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
                            title={`${slot.duration_minutes ?? '?'} min · ${slot.slot_type ?? 'in-person'}`}
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
                        <span className="text-[11px] text-slate-600">No slots</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="flex items-center gap-4 text-[11px] text-slate-500">
              <span className="inline-flex items-center gap-1.5">
                <MapPin className="w-3 h-3" /> in-person
              </span>
              <span className="inline-flex items-center gap-1.5">
                <Video className="w-3 h-3 text-sky-400" /> telehealth
              </span>
              {data.summary?.total_available_slots != null && (
                <span className="ml-auto tabular-nums">
                  {data.summary.total_available_slots} open slots
                </span>
              )}
            </div>
          </div>
        )}
      </Card>
    </section>
  )
}
