import React from 'react'
import { Activity, TrendingDown, ShieldCheck, BarChart3 } from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
  BarChart, Bar,
  PieChart as RPieChart, Pie, Cell,
} from 'recharts'

/* ── Vitals Trend Data (12 months) ─────────────────────────────── */

const vitalsTrendData = [
  { month: 'Mar', systolic: 142, diastolic: 88, heartRate: 78 },
  { month: 'Apr', systolic: 138, diastolic: 86, heartRate: 76 },
  { month: 'May', systolic: 136, diastolic: 84, heartRate: 74 },
  { month: 'Jun', systolic: 140, diastolic: 87, heartRate: 80 },
  { month: 'Jul', systolic: 134, diastolic: 82, heartRate: 72 },
  { month: 'Aug', systolic: 132, diastolic: 81, heartRate: 73 },
  { month: 'Sep', systolic: 130, diastolic: 80, heartRate: 71 },
  { month: 'Oct', systolic: 135, diastolic: 83, heartRate: 75 },
  { month: 'Nov', systolic: 128, diastolic: 79, heartRate: 70 },
  { month: 'Dec', systolic: 131, diastolic: 80, heartRate: 72 },
  { month: 'Jan', systolic: 126, diastolic: 78, heartRate: 69 },
  { month: 'Feb', systolic: 124, diastolic: 76, heartRate: 68 },
]

/* ── Readmission Risk Distribution ─────────────────────────────── */

const readmissionData = [
  { name: 'Low Risk', value: 58, color: '#10b981' },
  { name: 'Moderate Risk', value: 27, color: '#f59e0b' },
  { name: 'High Risk', value: 12, color: '#f97316' },
  { name: 'Critical Risk', value: 3, color: '#ef4444' },
]

/* ── Preventive Care Compliance ────────────────────────────────── */

const complianceData = [
  { category: 'Cancer Screening', compliant: 72, nonCompliant: 28 },
  { category: 'Cardiovascular', compliant: 81, nonCompliant: 19 },
  { category: 'Diabetes', compliant: 68, nonCompliant: 32 },
  { category: 'Immunizations', compliant: 85, nonCompliant: 15 },
  { category: "Women's Health", compliant: 64, nonCompliant: 36 },
]

/* ── Department Metrics ────────────────────────────────────────── */

interface DeptMetric {
  department: string
  patients: number
  avgLOS: number
  satisfaction: number
  readmitRate: number
  staffRatio: string
}

const departmentMetrics: DeptMetric[] = [
  { department: 'Internal Medicine', patients: 842, avgLOS: 3.2, satisfaction: 4.5, readmitRate: 8.2, staffRatio: '1:4' },
  { department: 'Cardiology', patients: 312, avgLOS: 4.8, satisfaction: 4.6, readmitRate: 11.4, staffRatio: '1:3' },
  { department: 'Pulmonology', patients: 198, avgLOS: 5.1, satisfaction: 4.3, readmitRate: 12.8, staffRatio: '1:3' },
  { department: 'Endocrinology', patients: 456, avgLOS: 2.1, satisfaction: 4.4, readmitRate: 5.6, staffRatio: '1:5' },
  { department: 'Orthopedics', patients: 287, avgLOS: 3.8, satisfaction: 4.7, readmitRate: 4.2, staffRatio: '1:4' },
  { department: 'Neurology', patients: 178, avgLOS: 4.5, satisfaction: 4.2, readmitRate: 9.8, staffRatio: '1:3' },
]

export default function HealthAnalytics() {
  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Health Analytics</h2>

      {/* Population Health KPIs */}
      <div className="grid grid-cols-4 gap-4">
        <KpiCard title="Avg HbA1c" value="7.1%" icon={Activity} detail="Target < 7.0% for most adults" />
        <KpiCard title="BP Control Rate" value="68.4%" icon={TrendingDown} detail="+4.2% vs last quarter" positive />
        <KpiCard title="Screening Compliance" value="74.2%" icon={ShieldCheck} detail="Across all preventive measures" positive />
        <KpiCard title="Readmission Rate" value="8.6%" icon={BarChart3} detail="30-day all-cause, target < 10%" positive />
      </div>

      {/* Vitals Trend + Readmission Pie */}
      <div className="grid grid-cols-3 gap-6">
        {/* Vitals Trend Chart (dual-axis) */}
        <div className="col-span-2 bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Patient Vitals Trend (12-Month)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={vitalsTrendData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
              <XAxis dataKey="month" stroke="#6b7280" fontSize={12} />
              <YAxis yAxisId="bp" stroke="#6b7280" fontSize={12} domain={[60, 160]} tickFormatter={(v: unknown) => `${Number(v)}`} />
              <YAxis yAxisId="hr" orientation="right" stroke="#6b7280" fontSize={12} domain={[50, 100]} tickFormatter={(v: unknown) => `${Number(v)}`} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                labelStyle={{ color: '#9ca3af' }}
                formatter={(value: unknown, name: string) => {
                  const numValue = Number(value)
                  const labels: Record<string, string> = {
                    systolic: 'Systolic BP',
                    diastolic: 'Diastolic BP',
                    heartRate: 'Heart Rate',
                  }
                  const units: Record<string, string> = {
                    systolic: 'mmHg',
                    diastolic: 'mmHg',
                    heartRate: 'bpm',
                  }
                  return [`${numValue} ${units[name] || ''}`, labels[name] || name]
                }}
              />
              <Legend
                formatter={(value: string) => {
                  const labels: Record<string, string> = {
                    systolic: 'Systolic BP',
                    diastolic: 'Diastolic BP',
                    heartRate: 'Heart Rate',
                  }
                  return <span className="text-xs text-gray-400">{labels[value] || value}</span>
                }}
              />
              <Line yAxisId="bp" type="monotone" dataKey="systolic" stroke="#e11d48" strokeWidth={2} dot={{ r: 3, fill: '#e11d48' }} />
              <Line yAxisId="bp" type="monotone" dataKey="diastolic" stroke="#fb7185" strokeWidth={2} dot={{ r: 3, fill: '#fb7185' }} />
              <Line yAxisId="hr" type="monotone" dataKey="heartRate" stroke="#8b5cf6" strokeWidth={2} dot={{ r: 3, fill: '#8b5cf6' }} strokeDasharray="4 4" />
            </LineChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-6 mt-2 text-xs text-gray-500">
            <span><span className="inline-block w-4 h-0.5 bg-rose-600 mr-1 align-middle" /> Systolic (mmHg)</span>
            <span><span className="inline-block w-4 h-0.5 bg-rose-400 mr-1 align-middle" /> Diastolic (mmHg)</span>
            <span><span className="inline-block w-4 h-0.5 bg-violet-500 mr-1 align-middle" style={{ borderTop: '1px dashed' }} /> Heart Rate (bpm)</span>
          </div>
        </div>

        {/* Readmission Risk Pie */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Readmission Risk Distribution</h3>
          <ResponsiveContainer width="100%" height={200}>
            <RPieChart>
              <Pie
                data={readmissionData}
                dataKey="value"
                cx="50%"
                cy="50%"
                innerRadius={45}
                outerRadius={80}
                paddingAngle={3}
              >
                {readmissionData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: unknown) => [`${Number(value)}%`, 'Patients']}
              />
            </RPieChart>
          </ResponsiveContainer>
          <div className="space-y-2 mt-2">
            {readmissionData.map((item) => (
              <div key={item.name} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ background: item.color }} />
                  <span className="text-xs text-gray-400">{item.name}</span>
                </div>
                <span className="text-xs font-medium text-white">{item.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Preventive Care Compliance Bar Chart */}
      <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
        <h3 className="text-sm font-medium text-gray-400 mb-4">Preventive Care Compliance by Category</h3>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={complianceData} margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
            <XAxis dataKey="category" stroke="#6b7280" fontSize={11} />
            <YAxis stroke="#6b7280" fontSize={12} tickFormatter={(v: unknown) => `${Number(v)}%`} />
            <Tooltip
              contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
              formatter={(value: unknown, name: string) => {
                const labels: Record<string, string> = { compliant: 'Compliant', nonCompliant: 'Non-Compliant' }
                return [`${Number(value)}%`, labels[name] || name]
              }}
            />
            <Legend
              formatter={(value: string) => {
                const labels: Record<string, string> = { compliant: 'Compliant', nonCompliant: 'Non-Compliant' }
                return <span className="text-xs text-gray-400">{labels[value] || value}</span>
              }}
            />
            <Bar dataKey="compliant" stackId="compliance" fill="#e11d48" radius={[0, 0, 0, 0]} />
            <Bar dataKey="nonCompliant" stackId="compliance" fill="#374151" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Department Metrics Table */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h3 className="text-sm font-medium text-gray-400">Department Performance Metrics</h3>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 text-left">Department</th>
              <th className="px-6 py-3 text-center">Patients</th>
              <th className="px-6 py-3 text-center">Avg LOS (days)</th>
              <th className="px-6 py-3 text-center">Satisfaction</th>
              <th className="px-6 py-3 text-center">Readmit Rate</th>
              <th className="px-6 py-3 text-center">Staff Ratio</th>
            </tr>
          </thead>
          <tbody>
            {departmentMetrics.map((dept) => (
              <tr key={dept.department} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-6 py-3">
                  <span className="font-medium text-rose-400">{dept.department}</span>
                </td>
                <td className="px-6 py-3 text-center text-gray-300 text-sm">{dept.patients.toLocaleString()}</td>
                <td className="px-6 py-3 text-center text-gray-400 text-sm">{dept.avgLOS}</td>
                <td className="px-6 py-3 text-center">
                  <div className="flex items-center justify-center gap-1">
                    <span className={`text-sm font-medium ${dept.satisfaction >= 4.5 ? 'text-green-400' : dept.satisfaction >= 4.0 ? 'text-yellow-400' : 'text-red-400'}`}>
                      {dept.satisfaction}
                    </span>
                    <span className="text-xs text-gray-500">/5</span>
                  </div>
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`text-sm font-medium ${dept.readmitRate <= 6 ? 'text-green-400' : dept.readmitRate <= 10 ? 'text-yellow-400' : 'text-red-400'}`}>
                    {dept.readmitRate}%
                  </span>
                </td>
                <td className="px-6 py-3 text-center text-gray-400 text-sm">{dept.staffRatio}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function KpiCard({ title, value, icon: Icon, detail, positive }: {
  title: string; value: string; icon: React.ElementType; detail: string; positive?: boolean
}) {
  return (
    <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className="w-5 h-5 text-gray-500" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className={`text-sm mt-1 ${positive ? 'text-green-400' : 'text-gray-400'}`}>{detail}</div>
    </div>
  )
}
