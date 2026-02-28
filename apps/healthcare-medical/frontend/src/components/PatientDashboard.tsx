import React from 'react'
import { Users, Calendar, Clock, AlertTriangle, Activity } from 'lucide-react'

interface Patient {
  name: string
  id: string
  age: number
  lastVisit: string
  primaryCondition: string
  riskLevel: 'High' | 'Medium' | 'Low'
  nextAppointment: string
}

const patients: Patient[] = [
  { name: 'Maria Garcia', id: 'PT-10042', age: 67, lastVisit: '2026-02-25', primaryCondition: 'Type 2 Diabetes', riskLevel: 'High', nextAppointment: '2026-03-04' },
  { name: 'James Wilson', id: 'PT-10089', age: 54, lastVisit: '2026-02-27', primaryCondition: 'Hypertension', riskLevel: 'Medium', nextAppointment: '2026-03-10' },
  { name: 'Sarah Chen', id: 'PT-10156', age: 42, lastVisit: '2026-02-20', primaryCondition: 'Asthma', riskLevel: 'Low', nextAppointment: '2026-03-15' },
  { name: 'Robert Johnson', id: 'PT-10203', age: 71, lastVisit: '2026-02-26', primaryCondition: 'CHF / Atrial Fibrillation', riskLevel: 'High', nextAppointment: '2026-03-01' },
  { name: 'Emily Davis', id: 'PT-10278', age: 35, lastVisit: '2026-02-22', primaryCondition: 'Anxiety / Depression', riskLevel: 'Low', nextAppointment: '2026-03-20' },
  { name: 'Michael Brown', id: 'PT-10312', age: 62, lastVisit: '2026-02-28', primaryCondition: 'COPD', riskLevel: 'High', nextAppointment: '2026-03-07' },
  { name: 'Linda Martinez', id: 'PT-10345', age: 58, lastVisit: '2026-02-24', primaryCondition: 'Rheumatoid Arthritis', riskLevel: 'Medium', nextAppointment: '2026-03-12' },
  { name: 'David Lee', id: 'PT-10401', age: 49, lastVisit: '2026-02-18', primaryCondition: 'Hyperlipidemia', riskLevel: 'Medium', nextAppointment: '2026-04-01' },
]

const riskColors: Record<string, string> = {
  'High': 'bg-red-900/30 text-red-400 border-red-800/50',
  'Medium': 'bg-yellow-900/30 text-yellow-400 border-yellow-800/50',
  'Low': 'bg-green-900/30 text-green-400 border-green-800/50',
}

interface Appointment {
  time: string
  patient: string
  provider: string
  type: string
}

const upcomingAppointments: Appointment[] = [
  { time: '09:00 AM', patient: 'Robert Johnson', provider: 'Dr. Patel', type: 'Cardiology Follow-up' },
  { time: '09:30 AM', patient: 'Maria Garcia', provider: 'Dr. Kim', type: 'Diabetes Management' },
  { time: '10:15 AM', patient: 'Michael Brown', provider: 'Dr. Patel', type: 'Pulmonary Function Test' },
  { time: '11:00 AM', patient: 'James Wilson', provider: 'Dr. Kim', type: 'Blood Pressure Review' },
  { time: '01:30 PM', patient: 'Linda Martinez', provider: 'Dr. Singh', type: 'Rheumatology Consult' },
]

interface CareGap {
  patient: string
  patientId: string
  type: string
  description: string
  dueDate: string
  overdueDays: number
  severity: 'Critical' | 'Warning' | 'Info'
}

const careGaps: CareGap[] = [
  { patient: 'Maria Garcia', patientId: 'PT-10042', type: 'Screening', description: 'Annual diabetic retinal exam overdue', dueDate: '2025-12-15', overdueDays: 75, severity: 'Critical' },
  { patient: 'Robert Johnson', patientId: 'PT-10203', type: 'Vaccination', description: 'Pneumococcal vaccine (PPSV23) due', dueDate: '2026-01-10', overdueDays: 49, severity: 'Critical' },
  { patient: 'Maria Garcia', patientId: 'PT-10042', type: 'Lab Work', description: 'HbA1c test overdue (quarterly)', dueDate: '2026-01-30', overdueDays: 29, severity: 'Warning' },
  { patient: 'David Lee', patientId: 'PT-10401', type: 'Screening', description: 'Colorectal cancer screening overdue', dueDate: '2026-02-01', overdueDays: 27, severity: 'Warning' },
  { patient: 'Michael Brown', patientId: 'PT-10312', type: 'Vaccination', description: 'Annual influenza vaccine due', dueDate: '2026-02-15', overdueDays: 13, severity: 'Info' },
  { patient: 'Linda Martinez', patientId: 'PT-10345', type: 'Lab Work', description: 'Liver function panel due (methotrexate monitoring)', dueDate: '2026-02-20', overdueDays: 8, severity: 'Info' },
]

const severityColors: Record<string, { text: string; bg: string; border: string }> = {
  'Critical': { text: 'text-red-400', bg: 'bg-red-900/20', border: 'border-red-800/40' },
  'Warning': { text: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-800/40' },
  'Info': { text: 'text-blue-400', bg: 'bg-blue-900/20', border: 'border-blue-800/40' },
}

export default function PatientDashboard() {
  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Patient Dashboard</h2>

      {/* Stat Cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard title="Active Patients" value="2,847" icon={Users} change="128 new this month" positive />
        <StatCard title="Appointments Today" value="42" icon={Calendar} change="6 remaining" highlight />
        <StatCard title="Avg Wait Time" value="14 min" icon={Clock} change="-3 min vs last week" positive />
        <StatCard title="Care Gap Alerts" value="156" icon={AlertTriangle} change="23 critical priority" />
      </div>

      {/* Recent Patients Table */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-medium text-gray-400">Recent Patients</h3>
          </div>
          <span className="text-xs text-gray-500">{patients.length} patients shown</span>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 text-left">Patient</th>
              <th className="px-6 py-3 text-left">ID</th>
              <th className="px-6 py-3 text-center">Age</th>
              <th className="px-6 py-3 text-left">Last Visit</th>
              <th className="px-6 py-3 text-left">Primary Condition</th>
              <th className="px-6 py-3 text-center">Risk Level</th>
              <th className="px-6 py-3 text-left">Next Appt</th>
            </tr>
          </thead>
          <tbody>
            {patients.map((patient) => (
              <tr key={patient.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-6 py-3">
                  <span className="font-medium text-gray-200">{patient.name}</span>
                </td>
                <td className="px-6 py-3">
                  <span className="font-medium text-rose-400">{patient.id}</span>
                </td>
                <td className="px-6 py-3 text-center text-gray-400 text-sm">{patient.age}</td>
                <td className="px-6 py-3 text-gray-400 text-sm">{patient.lastVisit}</td>
                <td className="px-6 py-3 text-gray-300 text-sm">{patient.primaryCondition}</td>
                <td className="px-6 py-3 text-center">
                  <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border ${riskColors[patient.riskLevel]}`}>
                    {patient.riskLevel}
                  </span>
                </td>
                <td className="px-6 py-3 text-gray-400 text-sm">{patient.nextAppointment}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Appointments + Care Gaps */}
      <div className="grid grid-cols-2 gap-6">
        {/* Upcoming Appointments */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
            <Calendar className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-medium text-gray-400">Upcoming Appointments</h3>
          </div>
          <div className="divide-y divide-gray-800/50">
            {upcomingAppointments.map((appt, i) => (
              <div key={i} className="px-6 py-4 flex items-center gap-4 hover:bg-gray-800/30">
                <div className="w-16 text-center flex-shrink-0">
                  <div className="text-sm font-bold text-rose-400">{appt.time}</div>
                </div>
                <div className="w-px h-10 bg-gray-700" />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-gray-200">{appt.patient}</div>
                  <div className="text-xs text-gray-500">{appt.type}</div>
                </div>
                <div className="text-right flex-shrink-0">
                  <div className="text-xs text-gray-400">{appt.provider}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Care Gap Alerts */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-medium text-gray-400">Care Gap Alerts</h3>
          </div>
          <div className="divide-y divide-gray-800/50">
            {careGaps.map((gap, i) => {
              const style = severityColors[gap.severity]
              return (
                <div key={i} className="px-6 py-4 hover:bg-gray-800/30">
                  <div className="flex items-start gap-3">
                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${style.bg} border ${style.border} flex-shrink-0 mt-0.5`}>
                      <span className={`text-xs font-bold ${style.text}`}>{gap.overdueDays}d</span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-gray-200">{gap.patient}</span>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${style.text} ${style.bg} border ${style.border}`}>
                          {gap.severity}
                        </span>
                      </div>
                      <p className="text-xs text-gray-400">{gap.description}</p>
                      <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
                        <span>{gap.type}</span>
                        <span>Due: {gap.dueDate}</span>
                        <span className="text-rose-400">{gap.overdueDays} days overdue</span>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon: Icon, change, positive, highlight }: {
  title: string; value: string; icon: React.ElementType; change: string; positive?: boolean; highlight?: boolean
}) {
  return (
    <div className={`bg-gray-900 rounded-xl p-5 border ${highlight ? 'border-rose-800/50' : 'border-gray-800'}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className="w-5 h-5 text-gray-500" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className={`text-sm mt-1 ${positive ? 'text-green-400' : 'text-gray-400'}`}>{change}</div>
    </div>
  )
}
