import { Card } from '../../finance/widgets'
import { StatusPill, type PillTone } from '../widgets'
import type { AppointmentsResponse } from '../types'

function statusTone(status?: string): { tone: PillTone; label: string } {
  const s = (status ?? '').toLowerCase()
  if (s === 'confirmed') return { tone: 'green', label: 'Confirmed' }
  if (s === 'pending confirmation') return { tone: 'amber', label: 'Pending Confirmation' }
  return { tone: 'slate', label: status ?? '—' }
}

export default function AppointmentsCard({
  appointments,
}: {
  appointments?: AppointmentsResponse
}) {
  const rows = appointments?.appointments ?? []

  return (
    <Card title={`Upcoming Appointments${rows.length ? ` (${rows.length})` : ''}`}>
      {rows.length === 0 ? (
        <p className="p-5 text-sm text-slate-500">No upcoming appointments.</p>
      ) : (
        <ul className="p-2 @lg:p-3 divide-y divide-slate-800/70">
          {rows.map((appt, i) => {
            const status = statusTone(appt.status)
            return (
              <li
                key={appt.appointment_id ?? i}
                className="px-2 py-2.5 flex flex-wrap items-center gap-x-3 gap-y-1"
              >
                <span className="text-xs text-slate-300 tabular-nums whitespace-nowrap w-28">
                  {appt.date ?? '—'} {appt.time ?? ''}
                </span>
                <span className="text-sm text-white flex-1 min-w-[120px]">
                  {appt.appointment_type ?? '—'}
                </span>
                <span className="text-xs text-slate-400">
                  {appt.provider?.name ?? '—'}
                </span>
                <StatusPill tone={status.tone} label={status.label} />
              </li>
            )
          })}
        </ul>
      )}
    </Card>
  )
}
