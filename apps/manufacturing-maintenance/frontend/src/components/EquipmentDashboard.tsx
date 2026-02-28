import React from 'react'
import { Settings, CheckCircle, AlertTriangle, Activity } from 'lucide-react'
import {
  PieChart as RPieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis,
} from 'recharts'

const equipmentHealth = [
  { name: 'EQ-CNC-001 CNC Lathe', health: 94, status: 'Operational' },
  { name: 'EQ-CNC-002 CNC Mill', health: 87, status: 'Operational' },
  { name: 'EQ-PMP-003 Hydraulic Pump', health: 62, status: 'Warning' },
  { name: 'EQ-CMP-004 Air Compressor', health: 45, status: 'Critical' },
  { name: 'EQ-CON-005 Conveyor Belt A', health: 91, status: 'Operational' },
  { name: 'EQ-WLD-006 Robotic Welder', health: 78, status: 'Warning' },
  { name: 'EQ-GRN-007 Surface Grinder', health: 83, status: 'Operational' },
  { name: 'EQ-PRS-008 Hydraulic Press', health: 38, status: 'Critical' },
  { name: 'EQ-CON-009 Conveyor Belt B', health: 96, status: 'Operational' },
  { name: 'EQ-DRL-010 Drill Press', health: 71, status: 'Warning' },
]

function getHealthColor(health: number): string {
  if (health > 80) return '#10b981'
  if (health >= 50) return '#f59e0b'
  return '#ef4444'
}

const statusDistribution = [
  { name: 'Operational', value: 14, color: '#10b981' },
  { name: 'Warning', value: 5, color: '#f59e0b' },
  { name: 'Critical', value: 3, color: '#ef4444' },
  { name: 'Offline', value: 2, color: '#6b7280' },
]

interface AlertItem {
  equipment: string
  alertType: string
  severity: string
  timestamp: string
  recommendedAction: string
}

const activeAlerts: AlertItem[] = [
  { equipment: 'EQ-CMP-004 Air Compressor', alertType: 'Vibration Anomaly', severity: 'Critical', timestamp: '2026-02-28 08:14', recommendedAction: 'Immediate bearing inspection required' },
  { equipment: 'EQ-PRS-008 Hydraulic Press', alertType: 'Temperature Spike', severity: 'Critical', timestamp: '2026-02-28 07:52', recommendedAction: 'Check hydraulic fluid levels and cooling system' },
  { equipment: 'EQ-PMP-003 Hydraulic Pump', alertType: 'Pressure Drop', severity: 'High', timestamp: '2026-02-28 06:30', recommendedAction: 'Inspect seals and check for leaks' },
  { equipment: 'EQ-WLD-006 Robotic Welder', alertType: 'Electrode Wear', severity: 'Medium', timestamp: '2026-02-28 05:45', recommendedAction: 'Schedule electrode replacement within 48h' },
  { equipment: 'EQ-DRL-010 Drill Press', alertType: 'Spindle Vibration', severity: 'Medium', timestamp: '2026-02-27 22:18', recommendedAction: 'Lubricate spindle bearings, monitor trend' },
  { equipment: 'EQ-CNC-002 CNC Mill', alertType: 'Tool Wear Alert', severity: 'Low', timestamp: '2026-02-27 19:05', recommendedAction: 'Plan tool change at next shift break' },
  { equipment: 'EQ-CON-005 Conveyor Belt A', alertType: 'Belt Tension', severity: 'Low', timestamp: '2026-02-27 16:32', recommendedAction: 'Adjust tension during scheduled downtime' },
  { equipment: 'EQ-GRN-007 Surface Grinder', alertType: 'Coolant Flow', severity: 'Low', timestamp: '2026-02-27 14:10', recommendedAction: 'Refill coolant reservoir and clean filters' },
]

const severityColors: Record<string, string> = {
  'Critical': 'bg-red-900/30 text-red-400 border-red-800/50',
  'High': 'bg-orange-900/30 text-orange-400 border-orange-800/50',
  'Medium': 'bg-yellow-900/30 text-yellow-400 border-yellow-800/50',
  'Low': 'bg-blue-900/30 text-blue-400 border-blue-800/50',
}

export default function EquipmentDashboard() {
  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Equipment Dashboard</h2>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard title="Total Equipment" value="24" icon={Settings} change="Across 3 production lines" />
        <StatCard title="Healthy %" value="87.5%" icon={CheckCircle} change="+2.1% vs last month" positive />
        <StatCard title="Critical Alerts" value="2" icon={AlertTriangle} change="Requires immediate action" highlight />
        <StatCard title="Avg OEE" value="84.6%" icon={Activity} change="+1.4% vs last quarter" positive />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-2 gap-6">
        {/* Equipment Health Horizontal Bar Chart */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Equipment Health Overview</h3>
          <ResponsiveContainer width="100%" height={340}>
            <BarChart
              data={equipmentHealth}
              layout="vertical"
              margin={{ top: 5, right: 30, left: 140, bottom: 5 }}
            >
              <XAxis type="number" domain={[0, 100]} stroke="#6b7280" fontSize={12} tickFormatter={(v: number) => `${v}%`} />
              <YAxis type="category" dataKey="name" stroke="#6b7280" fontSize={11} width={130} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: unknown) => [`${Number(value)}%`, 'Health Score']}
              />
              <Bar dataKey="health" radius={[0, 4, 4, 0]}>
                {equipmentHealth.map((entry, i) => (
                  <Cell key={i} fill={getHealthColor(entry.health)} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Equipment Status Distribution Donut */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Equipment Status Distribution</h3>
          <div className="flex items-center">
            <ResponsiveContainer width="55%" height={280}>
              <RPieChart>
                <Pie
                  data={statusDistribution}
                  dataKey="value"
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={3}
                >
                  {statusDistribution.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                  formatter={(value: unknown) => [`${Number(value)} units`, 'Count']}
                />
              </RPieChart>
            </ResponsiveContainer>
            <div className="flex-1 space-y-4">
              {statusDistribution.map((item) => (
                <div key={item.name}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full" style={{ background: item.color }} />
                      <span className="text-sm font-medium text-gray-300">{item.name}</span>
                    </div>
                    <span className="text-sm font-bold text-white">{item.value}</span>
                  </div>
                  <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${(item.value / 24) * 100}%`, background: item.color }}
                    />
                  </div>
                  <div className="text-[10px] text-gray-600 mt-0.5">
                    {((item.value / 24) * 100).toFixed(1)}% of fleet
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Active Alerts Table */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-medium text-gray-400">Active Alerts</h3>
          </div>
          <span className="text-xs text-gray-500">{activeAlerts.length} active alerts</span>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 text-left">Equipment</th>
              <th className="px-6 py-3 text-left">Alert Type</th>
              <th className="px-6 py-3 text-center">Severity</th>
              <th className="px-6 py-3 text-left">Timestamp</th>
              <th className="px-6 py-3 text-left">Recommended Action</th>
            </tr>
          </thead>
          <tbody>
            {activeAlerts.map((alert, idx) => (
              <tr key={idx} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-6 py-3">
                  <span className="font-medium text-amber-400">{alert.equipment}</span>
                </td>
                <td className="px-6 py-3 text-sm text-gray-300">{alert.alertType}</td>
                <td className="px-6 py-3 text-center">
                  <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border ${severityColors[alert.severity]}`}>
                    {alert.severity}
                  </span>
                </td>
                <td className="px-6 py-3 text-sm text-gray-400">{alert.timestamp}</td>
                <td className="px-6 py-3 text-sm text-gray-400">{alert.recommendedAction}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon: Icon, change, positive, highlight }: {
  title: string; value: string; icon: React.ElementType; change: string; positive?: boolean; highlight?: boolean
}) {
  return (
    <div className={`bg-gray-900 rounded-xl p-5 border ${highlight ? 'border-amber-800/50' : 'border-gray-800'}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className="w-5 h-5 text-gray-500" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className={`text-sm mt-1 ${positive ? 'text-green-400' : 'text-gray-400'}`}>{change}</div>
    </div>
  )
}
