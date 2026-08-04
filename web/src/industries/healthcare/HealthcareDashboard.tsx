import { useState } from 'react'
import { SimulatedBadge } from '../finance/widgets'
import PracticePulseSection from './PracticePulseSection'
import PatientSection from './PatientSection'
import SchedulingSection from './SchedulingSection'

const DEFAULT_PATIENT_ID = 'PT-1001'

export default function HealthcareDashboard() {
  // Lifted so Patient 360 and Scheduling share the same active patient.
  const [patientId, setPatientId] = useState(DEFAULT_PATIENT_ID)

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-4 lg:p-6 space-y-6 @container">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg lg:text-xl font-bold text-white">
            Healthcare &amp; Medical
          </h2>
          <SimulatedBadge />
        </div>

        <PracticePulseSection />
        <PatientSection patientId={patientId} onPatientChange={setPatientId} />
        <SchedulingSection patientId={patientId} />
      </div>
    </div>
  )
}
