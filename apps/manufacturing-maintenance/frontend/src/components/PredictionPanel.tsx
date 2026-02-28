import React from 'react'
import { Gauge, Cpu, BarChart3, Zap } from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  ScatterChart, Scatter, Cell, ReferenceLine, Legend,
} from 'recharts'

interface PredictionItem {
  equipment: string
  equipmentId: string
  rulDays: number
  failureProbability: number
  failureMode: string
  confidence: number
}

const predictions: PredictionItem[] = [
  { equipment: 'Air Compressor', equipmentId: 'EQ-CMP-004', rulDays: 12, failureProbability: 87, failureMode: 'Bearing Degradation', confidence: 92 },
  { equipment: 'Hydraulic Press', equipmentId: 'EQ-PRS-008', rulDays: 8, failureProbability: 91, failureMode: 'Seal Failure', confidence: 88 },
  { equipment: 'Hydraulic Pump', equipmentId: 'EQ-PMP-003', rulDays: 34, failureProbability: 58, failureMode: 'Impeller Wear', confidence: 79 },
  { equipment: 'Robotic Welder', equipmentId: 'EQ-WLD-006', rulDays: 52, failureProbability: 41, failureMode: 'Motor Brush Wear', confidence: 85 },
  { equipment: 'Drill Press', equipmentId: 'EQ-DRL-010', rulDays: 67, failureProbability: 29, failureMode: 'Spindle Misalignment', confidence: 74 },
]

function getRulColor(days: number): string {
  if (days <= 14) return '#ef4444'
  if (days <= 30) return '#f59e0b'
  return '#10b981'
}

function getRulBg(days: number): string {
  if (days <= 14) return 'bg-red-900/20 border-red-800/40'
  if (days <= 30) return 'bg-yellow-900/20 border-yellow-800/40'
  return 'bg-green-900/20 border-green-800/40'
}

// Sensor trend data: 7 days of temperature + vibration
const sensorTrendData = Array.from({ length: 168 }, (_, i) => {
  const hour = i
  const day = Math.floor(i / 24) + 1
  const h = i % 24
  const baseTemp = 72 + Math.sin(h / 24 * Math.PI * 2) * 5
  const tempTrend = day * 1.2
  const tempNoise = (Math.random() - 0.5) * 4
  const temperature = Math.round((baseTemp + tempTrend + tempNoise + (day > 5 ? (day - 5) * 2.5 : 0)) * 10) / 10

  const baseVib = 2.1 + Math.sin(h / 12 * Math.PI) * 0.3
  const vibTrend = day * 0.15
  const vibNoise = (Math.random() - 0.5) * 0.4
  const vibration = Math.round((baseVib + vibTrend + vibNoise + (day > 5 ? (day - 5) * 0.4 : 0)) * 100) / 100

  return {
    hour,
    label: `D${day} ${h}:00`,
    temperature,
    vibration,
  }
}).filter((_, i) => i % 4 === 0) // Sample every 4 hours

const reliabilityMetrics = [
  { label: 'MTBF', value: 842, unit: 'hours', benchmark: 720, icon: Gauge, description: 'Mean Time Between Failures' },
  { label: 'MTTR', value: 4.2, unit: 'hours', benchmark: 6.0, icon: Zap, description: 'Mean Time To Repair' },
  { label: 'OEE', value: 84.6, unit: '%', benchmark: 85.0, icon: BarChart3, description: 'Overall Equipment Effectiveness' },
  { label: 'Availability', value: 96.2, unit: '%', benchmark: 95.0, icon: Cpu, description: 'Equipment Availability Rate' },
]

// Anomaly scatter data
const anomalyData = Array.from({ length: 45 }, (_, i) => {
  const daysAgo = Math.floor(Math.random() * 30)
  const severityVal = Math.random()
  const severity = severityVal > 0.85 ? 'Critical' : severityVal > 0.6 ? 'High' : severityVal > 0.3 ? 'Medium' : 'Low'
  const severityScore = severity === 'Critical' ? 90 + Math.random() * 10 : severity === 'High' ? 70 + Math.random() * 20 : severity === 'Medium' ? 40 + Math.random() * 30 : 10 + Math.random() * 30
  return {
    id: i,
    day: 30 - daysAgo,
    severity,
    severityScore: Math.round(severityScore),
    hour: Math.floor(Math.random() * 24),
  }
})

const anomalyColors: Record<string, string> = {
  'Critical': '#ef4444',
  'High': '#f97316',
  'Medium': '#f59e0b',
  'Low': '#6b7280',
}

export default function PredictionPanel() {
  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Failure Predictions & Analysis</h2>

      {/* Failure Prediction Cards */}
      <div className="grid grid-cols-5 gap-4">
        {predictions.map((pred) => (
          <div key={pred.equipmentId} className={`bg-gray-900 rounded-xl p-4 border ${getRulBg(pred.rulDays)}`}>
            <div className="text-xs text-gray-500 mb-1">{pred.equipmentId}</div>
            <div className="text-sm font-medium text-gray-200 mb-3">{pred.equipment}</div>

            {/* RUL Gauge */}
            <div className="flex items-center justify-center mb-3">
              <div className="relative w-20 h-20">
                <svg className="w-20 h-20 transform -rotate-90" viewBox="0 0 80 80">
                  <circle cx="40" cy="40" r="34" fill="none" stroke="#374151" strokeWidth="6" />
                  <circle
                    cx="40" cy="40" r="34" fill="none"
                    stroke={getRulColor(pred.rulDays)}
                    strokeWidth="6"
                    strokeLinecap="round"
                    strokeDasharray={`${(Math.min(pred.rulDays, 90) / 90) * 213.6} 213.6`}
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-lg font-bold" style={{ color: getRulColor(pred.rulDays) }}>{pred.rulDays}</span>
                  <span className="text-[10px] text-gray-500">days</span>
                </div>
              </div>
            </div>

            {/* Failure Probability Bar */}
            <div className="mb-2">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-gray-500">Failure Prob.</span>
                <span className="font-medium" style={{ color: getRulColor(pred.rulDays) }}>{pred.failureProbability}%</span>
              </div>
              <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all"
                  style={{ width: `${pred.failureProbability}%`, background: getRulColor(pred.rulDays) }}
                />
              </div>
            </div>

            <div className="text-xs text-gray-400 mb-1">
              <span className="text-gray-500">Mode: </span>{pred.failureMode}
            </div>
            <div className="text-xs text-gray-400">
              <span className="text-gray-500">Confidence: </span>
              <span className="text-amber-400">{pred.confidence}%</span>
            </div>
          </div>
        ))}
      </div>

      {/* Sensor Trend Chart */}
      <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
        <h3 className="text-sm font-medium text-gray-400 mb-4">Sensor Trend: Temperature & Vibration (7 Days) - EQ-CMP-004</h3>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={sensorTrendData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
            <XAxis dataKey="label" stroke="#6b7280" fontSize={10} interval={5} />
            <YAxis yAxisId="temp" stroke="#ef4444" fontSize={12} domain={[60, 100]} tickFormatter={(v: number) => `${v}F`} />
            <YAxis yAxisId="vib" orientation="right" stroke="#8b5cf6" fontSize={12} domain={[0, 6]} tickFormatter={(v: number) => `${v} mm/s`} />
            <Tooltip
              contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
              formatter={(value: unknown, name: string) => {
                const numVal = Number(value)
                if (name === 'temperature') return [`${numVal.toFixed(1)} F`, 'Temperature']
                return [`${numVal.toFixed(2)} mm/s`, 'Vibration']
              }}
            />
            <Legend formatter={(value: string) => {
              const labels: Record<string, string> = { temperature: 'Temperature (F)', vibration: 'Vibration (mm/s)' }
              return <span className="text-xs text-gray-400">{labels[value] || value}</span>
            }} />
            <ReferenceLine yAxisId="temp" y={90} stroke="#ef4444" strokeDasharray="6 4" label={{ value: 'Temp Threshold', fill: '#ef4444', fontSize: 10, position: 'right' }} />
            <ReferenceLine yAxisId="vib" y={4.5} stroke="#8b5cf6" strokeDasharray="6 4" label={{ value: 'Vib Threshold', fill: '#8b5cf6', fontSize: 10, position: 'right' }} />
            <Line yAxisId="temp" type="monotone" dataKey="temperature" stroke="#ef4444" strokeWidth={1.5} dot={false} />
            <Line yAxisId="vib" type="monotone" dataKey="vibration" stroke="#8b5cf6" strokeWidth={1.5} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Reliability Metrics + Anomaly Timeline */}
      <div className="grid grid-cols-2 gap-6">
        {/* Reliability Metrics */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Reliability Metrics</h3>
          <div className="grid grid-cols-2 gap-4">
            {reliabilityMetrics.map((metric) => {
              const pct = metric.unit === '%'
                ? metric.value / 100
                : metric.label === 'MTTR'
                  ? 1 - (metric.value / 10)
                  : Math.min(metric.value / (metric.benchmark * 1.5), 1)
              const isBetter = metric.label === 'MTTR'
                ? metric.value < metric.benchmark
                : metric.value >= metric.benchmark
              const MetricIcon = metric.icon
              return (
                <div key={metric.label} className="bg-gray-800/50 rounded-lg p-4 border border-gray-700/50">
                  <div className="flex items-center gap-2 mb-2">
                    <MetricIcon className="w-4 h-4 text-amber-400" />
                    <span className="text-xs text-gray-400">{metric.description}</span>
                  </div>
                  <div className="flex items-center justify-center mb-2">
                    <div className="relative w-16 h-16">
                      <svg className="w-16 h-16 transform -rotate-90" viewBox="0 0 64 64">
                        <circle cx="32" cy="32" r="26" fill="none" stroke="#374151" strokeWidth="5" />
                        <circle
                          cx="32" cy="32" r="26" fill="none"
                          stroke={isBetter ? '#10b981' : '#f59e0b'}
                          strokeWidth="5"
                          strokeLinecap="round"
                          strokeDasharray={`${pct * 163.4} 163.4`}
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-sm font-bold text-white">{metric.value}</span>
                      </div>
                    </div>
                  </div>
                  <div className="text-center">
                    <span className="text-lg font-bold text-white">{metric.label}</span>
                    <span className="text-xs text-gray-500 ml-1">{metric.unit}</span>
                  </div>
                  <div className="text-center text-xs mt-1">
                    <span className="text-gray-500">Benchmark: </span>
                    <span className={isBetter ? 'text-green-400' : 'text-yellow-400'}>{metric.benchmark} {metric.unit}</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Anomaly Timeline */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Anomaly Detection Timeline (Last 30 Days)</h3>
          <ResponsiveContainer width="100%" height={280}>
            <ScatterChart margin={{ top: 10, right: 20, left: 10, bottom: 10 }}>
              <XAxis type="number" dataKey="day" name="Day" stroke="#6b7280" fontSize={12} domain={[0, 30]} label={{ value: 'Days Ago (30=oldest)', position: 'bottom', fill: '#6b7280', fontSize: 10 }} />
              <YAxis type="number" dataKey="severityScore" name="Severity" stroke="#6b7280" fontSize={12} domain={[0, 100]} label={{ value: 'Severity', angle: -90, position: 'insideLeft', fill: '#6b7280', fontSize: 10 }} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: unknown, name: string) => {
                  if (name === 'Severity') return [`${Number(value)}`, 'Severity Score']
                  return [`Day ${Number(value)}`, 'Timeline']
                }}
              />
              <ReferenceLine y={80} stroke="#ef4444" strokeDasharray="4 4" />
              <ReferenceLine y={50} stroke="#f59e0b" strokeDasharray="4 4" />
              <Scatter data={anomalyData} name="Anomalies">
                {anomalyData.map((entry, i) => (
                  <Cell key={i} fill={anomalyColors[entry.severity]} />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-4 mt-2 text-xs text-gray-500">
            {Object.entries(anomalyColors).map(([label, color]) => (
              <span key={label} className="flex items-center gap-1">
                <span className="inline-block w-2.5 h-2.5 rounded-full" style={{ background: color }} />
                {label}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
