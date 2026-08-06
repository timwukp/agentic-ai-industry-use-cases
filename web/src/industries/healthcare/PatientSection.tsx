import { useState } from 'react'
import type { FormEvent } from 'react'
import { Search } from 'lucide-react'
import { useApi } from '../../lib/api'
import { useLocale } from '../../i18n/LocaleContext'
import { Card, ErrorPane, LoadingPane } from '../finance/widgets'
import { SectionHeader } from './widgets'
import type { PatientResponse } from './types'
import PatientHeaderCard from './cards/PatientHeaderCard'
import CareGapsCard from './cards/CareGapsCard'
import ReadmissionRiskCard from './cards/ReadmissionRiskCard'
import VitalsTrendsCard from './cards/VitalsTrendsCard'
import LabsMedsCard from './cards/LabsMedsCard'
import RiskScoresCard from './cards/RiskScoresCard'
import AppointmentsCard from './cards/AppointmentsCard'

const SUGGESTED_PATIENTS = ['PT-1001', 'PT-1002', 'PT-1003']

export default function PatientSection({
  patientId,
  onPatientChange,
}: {
  patientId: string
  onPatientChange: (id: string) => void
}) {
  const { t } = useLocale()
  const [inputValue, setInputValue] = useState('')

  const { data, loading, error, reload } = useApi<PatientResponse>(
    `/api/healthcare/patient?patientId=${encodeURIComponent(patientId)}`,
  )

  const apply = (event: FormEvent) => {
    event.preventDefault()
    const next = inputValue.trim().toUpperCase()
    if (next) {
      onPatientChange(next)
      setInputValue('')
    }
  }

  const picker = (
    <div className="flex flex-wrap items-center gap-2">
      {SUGGESTED_PATIENTS.map((id) => (
        <button
          key={id}
          type="button"
          onClick={() => onPatientChange(id)}
          className={`px-2.5 py-1.5 text-xs rounded-lg border tabular-nums transition-colors ${
            id === patientId
              ? 'bg-rose-600 border-rose-500 text-white'
              : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
          }`}
        >
          {id}
        </button>
      ))}
      <form onSubmit={apply} className="flex items-center gap-2">
        <input
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          placeholder={t('healthcare.patientIdPlaceholder')}
          aria-label={t('healthcare.patientIdLabel')}
          className="w-24 px-2.5 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-rose-500/60"
        />
        <button
          type="submit"
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 transition-colors"
        >
          <Search className="w-3.5 h-3.5" />
          {t('healthcare.apply')}
        </button>
      </form>
    </div>
  )

  return (
    <section className="space-y-4 @container">
      <SectionHeader title={t('healthcare.patient360')} action={picker} />

      {loading ? (
        <LoadingPane label={t('healthcare.loadingPatient', { id: patientId })} />
      ) : error || !data || data.error ? (
        <Card title={t('healthcare.patientTitle', { id: patientId })}>
          <ErrorPane
            message={error ?? data?.error ?? t('healthcare.noPatientData', { id: patientId })}
            onRetry={reload}
          />
        </Card>
      ) : (
        <div className="space-y-3 @lg:space-y-4">
          <PatientHeaderCard summary={data.summary} />
          <div className="grid grid-cols-1 @4xl:grid-cols-2 gap-3 @lg:gap-4">
            <CareGapsCard careGaps={data.care_gaps} patientId={patientId} />
            <ReadmissionRiskCard risk={data.readmission} patientId={patientId} />
          </div>
          <VitalsTrendsCard analytics={data.analytics} />
          <div className="grid grid-cols-1 @4xl:grid-cols-2 gap-3 @lg:gap-4">
            <LabsMedsCard patientId={patientId} />
            <div className="space-y-3 @lg:space-y-4">
              <RiskScoresCard patientId={patientId} />
              <AppointmentsCard appointments={data.appointments} />
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
