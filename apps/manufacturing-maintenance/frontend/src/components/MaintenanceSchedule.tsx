import React from 'react'
import { Calendar, AlertTriangle, CheckCircle, Package } from 'lucide-react'

// KPI data
const kpis = {
  scheduledThisWeek: 12,
  overdue: 3,
  completedMTD: 47,
  partsAvailability: 94.2,
}

// Weekly calendar data
interface CalendarTask {
  name: string
  equipment: string
  type: 'Preventive' | 'Predictive' | 'Corrective' | 'Inspection'
  priority: 'Critical' | 'High' | 'Medium' | 'Low'
}

const typeColors: Record<string, string> = {
  'Preventive': 'bg-blue-900/40 text-blue-400 border-blue-800/50',
  'Predictive': 'bg-amber-900/40 text-amber-400 border-amber-800/50',
  'Corrective': 'bg-red-900/40 text-red-400 border-red-800/50',
  'Inspection': 'bg-green-900/40 text-green-400 border-green-800/50',
}

const weeklyCalendar: Record<string, CalendarTask[]> = {
  Mon: [
    { name: 'Bearing Replacement', equipment: 'EQ-CMP-004', type: 'Corrective', priority: 'Critical' },
    { name: 'Oil Analysis', equipment: 'EQ-PRS-008', type: 'Predictive', priority: 'High' },
  ],
  Tue: [
    { name: 'Vibration Check', equipment: 'EQ-PMP-003', type: 'Inspection', priority: 'Medium' },
    { name: 'Filter Replacement', equipment: 'EQ-CNC-001', type: 'Preventive', priority: 'Low' },
    { name: 'Seal Inspection', equipment: 'EQ-PRS-008', type: 'Predictive', priority: 'High' },
  ],
  Wed: [
    { name: 'Electrode Change', equipment: 'EQ-WLD-006', type: 'Preventive', priority: 'Medium' },
  ],
  Thu: [
    { name: 'Belt Tension Adj.', equipment: 'EQ-CON-005', type: 'Preventive', priority: 'Low' },
    { name: 'Thermal Imaging', equipment: 'EQ-CMP-004', type: 'Predictive', priority: 'High' },
  ],
  Fri: [
    { name: 'Spindle Alignment', equipment: 'EQ-DRL-010', type: 'Corrective', priority: 'Medium' },
    { name: 'Coolant System', equipment: 'EQ-GRN-007', type: 'Preventive', priority: 'Low' },
    { name: 'Hydraulic Test', equipment: 'EQ-PMP-003', type: 'Inspection', priority: 'Medium' },
  ],
  Sat: [
    { name: 'Full PM Cycle', equipment: 'EQ-CNC-002', type: 'Preventive', priority: 'Medium' },
  ],
  Sun: [],
}

// Work orders
interface WorkOrder {
  woNumber: string
  equipment: string
  type: 'Preventive' | 'Predictive' | 'Corrective' | 'Emergency'
  priority: 'Critical' | 'High' | 'Medium' | 'Low'
  assignee: string
  dueDate: string
  status: 'Open' | 'In Progress' | 'On Hold' | 'Completed'
}

const workOrders: WorkOrder[] = [
  { woNumber: 'WO-2026-0891', equipment: 'EQ-CMP-004 Air Compressor', type: 'Corrective', priority: 'Critical', assignee: 'Mike Torres', dueDate: '2026-03-01', status: 'In Progress' },
  { woNumber: 'WO-2026-0892', equipment: 'EQ-PRS-008 Hydraulic Press', type: 'Predictive', priority: 'Critical', assignee: 'Sarah Chen', dueDate: '2026-03-02', status: 'Open' },
  { woNumber: 'WO-2026-0885', equipment: 'EQ-PMP-003 Hydraulic Pump', type: 'Predictive', priority: 'High', assignee: 'James Wilson', dueDate: '2026-03-03', status: 'Open' },
  { woNumber: 'WO-2026-0878', equipment: 'EQ-WLD-006 Robotic Welder', type: 'Preventive', priority: 'Medium', assignee: 'Lisa Park', dueDate: '2026-03-04', status: 'On Hold' },
  { woNumber: 'WO-2026-0870', equipment: 'EQ-DRL-010 Drill Press', type: 'Corrective', priority: 'Medium', assignee: 'Mike Torres', dueDate: '2026-03-05', status: 'Open' },
  { woNumber: 'WO-2026-0865', equipment: 'EQ-CNC-001 CNC Lathe', type: 'Preventive', priority: 'Low', assignee: 'Sarah Chen', dueDate: '2026-03-06', status: 'Completed' },
  { woNumber: 'WO-2026-0860', equipment: 'EQ-CON-005 Conveyor Belt A', type: 'Preventive', priority: 'Low', assignee: 'James Wilson', dueDate: '2026-03-07', status: 'Completed' },
  { woNumber: 'WO-2026-0856', equipment: 'EQ-GRN-007 Surface Grinder', type: 'Emergency', priority: 'High', assignee: 'Lisa Park', dueDate: '2026-02-28', status: 'In Progress' },
]

const woTypeColors: Record<string, string> = {
  'Preventive': 'bg-blue-900/30 text-blue-400 border-blue-800/50',
  'Predictive': 'bg-amber-900/30 text-amber-400 border-amber-800/50',
  'Corrective': 'bg-orange-900/30 text-orange-400 border-orange-800/50',
  'Emergency': 'bg-red-900/30 text-red-400 border-red-800/50',
}

const priorityColors: Record<string, string> = {
  'Critical': 'bg-red-900/30 text-red-400 border-red-800/50',
  'High': 'bg-orange-900/30 text-orange-400 border-orange-800/50',
  'Medium': 'bg-yellow-900/30 text-yellow-400 border-yellow-800/50',
  'Low': 'bg-green-900/30 text-green-400 border-green-800/50',
}

const statusColors: Record<string, string> = {
  'Open': 'bg-blue-900/30 text-blue-400 border-blue-800/50',
  'In Progress': 'bg-amber-900/30 text-amber-400 border-amber-800/50',
  'On Hold': 'bg-gray-800 text-gray-400 border-gray-700',
  'Completed': 'bg-green-900/30 text-green-400 border-green-800/50',
}

// Parts forecast
interface PartsForecast {
  partNumber: string
  description: string
  neededBy: string
  quantity: number
  stockStatus: 'In Stock' | 'Low Stock' | 'Out of Stock' | 'On Order'
}

const partsForecast: PartsForecast[] = [
  { partNumber: 'SKF-6205-2RS', description: 'Deep Groove Ball Bearing 25x52x15mm', neededBy: '2026-03-01', quantity: 4, stockStatus: 'In Stock' },
  { partNumber: 'PAR-HYD-032', description: 'Hydraulic Cylinder Seal Kit', neededBy: '2026-03-02', quantity: 2, stockStatus: 'In Stock' },
  { partNumber: 'FLT-AIR-019', description: 'Compressor Air Filter Element', neededBy: '2026-03-03', quantity: 6, stockStatus: 'Low Stock' },
  { partNumber: 'BLT-CON-044', description: 'Conveyor Drive Belt 2400mm', neededBy: '2026-03-05', quantity: 1, stockStatus: 'On Order' },
  { partNumber: 'ELC-WLD-007', description: 'Welding Electrode Tip Set (10pc)', neededBy: '2026-03-04', quantity: 3, stockStatus: 'In Stock' },
  { partNumber: 'OIL-HYD-015', description: 'Hydraulic Oil ISO VG 46 (20L)', neededBy: '2026-03-06', quantity: 8, stockStatus: 'Low Stock' },
  { partNumber: 'BRG-SPN-021', description: 'Spindle Taper Roller Bearing', neededBy: '2026-03-07', quantity: 2, stockStatus: 'Out of Stock' },
  { partNumber: 'CLN-GRN-009', description: 'Grinding Coolant Concentrate (5L)', neededBy: '2026-03-08', quantity: 4, stockStatus: 'In Stock' },
]

const stockStatusColors: Record<string, string> = {
  'In Stock': 'bg-green-900/30 text-green-400 border-green-800/50',
  'Low Stock': 'bg-yellow-900/30 text-yellow-400 border-yellow-800/50',
  'Out of Stock': 'bg-red-900/30 text-red-400 border-red-800/50',
  'On Order': 'bg-blue-900/30 text-blue-400 border-blue-800/50',
}

export default function MaintenanceSchedule() {
  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Maintenance Schedule</h2>

      {/* KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        <KpiCard title="Scheduled This Week" value={`${kpis.scheduledThisWeek}`} icon={Calendar} detail="Across all equipment" />
        <KpiCard title="Overdue" value={`${kpis.overdue}`} icon={AlertTriangle} detail="Requires immediate attention" highlight />
        <KpiCard title="Completed MTD" value={`${kpis.completedMTD}`} icon={CheckCircle} detail="+8 vs last month" positive />
        <KpiCard title="Parts Availability" value={`${kpis.partsAvailability}%`} icon={Package} detail="For scheduled tasks" positive />
      </div>

      {/* Weekly Calendar View */}
      <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
        <h3 className="text-sm font-medium text-gray-400 mb-4">Weekly Maintenance Calendar</h3>
        <div className="grid grid-cols-7 gap-2">
          {Object.entries(weeklyCalendar).map(([day, tasks]) => (
            <div key={day} className="min-h-[180px]">
              <div className="text-center text-xs font-medium text-gray-400 mb-2 pb-2 border-b border-gray-800">
                {day}
              </div>
              <div className="space-y-1.5">
                {tasks.length === 0 && (
                  <div className="text-center text-xs text-gray-600 py-4">No tasks</div>
                )}
                {tasks.map((task, idx) => (
                  <div
                    key={idx}
                    className={`p-2 rounded-lg border text-xs ${typeColors[task.type]}`}
                  >
                    <div className="font-medium truncate">{task.name}</div>
                    <div className="text-[10px] opacity-70 truncate">{task.equipment}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="flex justify-center gap-4 mt-4 pt-3 border-t border-gray-800 text-xs text-gray-500">
          {Object.entries(typeColors).map(([label, classes]) => (
            <span key={label} className="flex items-center gap-1.5">
              <span className={`inline-block w-3 h-3 rounded border ${classes}`} />
              {label}
            </span>
          ))}
        </div>
      </div>

      {/* Work Orders Table */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h3 className="text-sm font-medium text-gray-400">Work Orders</h3>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 text-left">WO #</th>
              <th className="px-6 py-3 text-left">Equipment</th>
              <th className="px-6 py-3 text-center">Type</th>
              <th className="px-6 py-3 text-center">Priority</th>
              <th className="px-6 py-3 text-left">Assignee</th>
              <th className="px-6 py-3 text-left">Due Date</th>
              <th className="px-6 py-3 text-center">Status</th>
            </tr>
          </thead>
          <tbody>
            {workOrders.map((wo) => (
              <tr key={wo.woNumber} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-6 py-3">
                  <span className="font-medium text-amber-400">{wo.woNumber}</span>
                </td>
                <td className="px-6 py-3 text-sm text-gray-300">{wo.equipment}</td>
                <td className="px-6 py-3 text-center">
                  <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border ${woTypeColors[wo.type]}`}>
                    {wo.type}
                  </span>
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border ${priorityColors[wo.priority]}`}>
                    {wo.priority}
                  </span>
                </td>
                <td className="px-6 py-3 text-sm text-gray-300">{wo.assignee}</td>
                <td className="px-6 py-3 text-sm text-gray-400">{wo.dueDate}</td>
                <td className="px-6 py-3 text-center">
                  <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border ${statusColors[wo.status]}`}>
                    {wo.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Parts Forecast Table */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Package className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-medium text-gray-400">Parts Forecast</h3>
          </div>
          <span className="text-xs text-gray-500">{partsForecast.length} parts needed</span>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 text-left">Part Number</th>
              <th className="px-6 py-3 text-left">Description</th>
              <th className="px-6 py-3 text-left">Needed By</th>
              <th className="px-6 py-3 text-center">Qty</th>
              <th className="px-6 py-3 text-center">Stock Status</th>
            </tr>
          </thead>
          <tbody>
            {partsForecast.map((part) => (
              <tr key={part.partNumber} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-6 py-3">
                  <span className="font-medium text-amber-400">{part.partNumber}</span>
                </td>
                <td className="px-6 py-3 text-sm text-gray-300">{part.description}</td>
                <td className="px-6 py-3 text-sm text-gray-400">{part.neededBy}</td>
                <td className="px-6 py-3 text-center text-sm text-white font-medium">{part.quantity}</td>
                <td className="px-6 py-3 text-center">
                  <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border ${stockStatusColors[part.stockStatus]}`}>
                    {part.stockStatus}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function KpiCard({ title, value, icon: Icon, detail, positive, highlight }: {
  title: string; value: string; icon: React.ElementType; detail: string; positive?: boolean; highlight?: boolean
}) {
  return (
    <div className={`bg-gray-900 rounded-xl p-5 border ${highlight ? 'border-amber-800/50' : 'border-gray-800'}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className="w-5 h-5 text-gray-500" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className={`text-sm mt-1 ${positive ? 'text-green-400' : 'text-gray-400'}`}>{detail}</div>
    </div>
  )
}
