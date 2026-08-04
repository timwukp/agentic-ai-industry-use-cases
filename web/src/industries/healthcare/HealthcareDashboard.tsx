import { SimulatedBadge } from '../finance/widgets'
import AvailabilitySection from './AvailabilitySection'
import PatientSection from './PatientSection'
import PopulationSection from './PopulationSection'

export default function HealthcareDashboard() {
  return (
    <div className="h-full overflow-y-auto">
      <div className="p-4 lg:p-6 space-y-6 @container">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg lg:text-xl font-bold text-white">
            Healthcare &amp; Medical
          </h2>
          <SimulatedBadge />
        </div>

        <PopulationSection />
        <PatientSection />
        <AvailabilitySection />
      </div>
    </div>
  )
}
