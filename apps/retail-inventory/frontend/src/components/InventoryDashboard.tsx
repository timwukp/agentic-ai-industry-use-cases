import React from 'react'
import { Package, CheckCircle, DollarSign, RefreshCw, AlertTriangle } from 'lucide-react'
import {
  PieChart as RPieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, Legend,
} from 'recharts'

const abcData = [
  { name: 'A Items', count: 245, value: 4250000, pctValue: 72, color: '#10b981' },
  { name: 'B Items', count: 612, value: 1180000, pctValue: 20, color: '#f59e0b' },
  { name: 'C Items', count: 1893, value: 470000, pctValue: 8, color: '#6b7280' },
]

const stockHealthData = [
  { category: 'Electronics', inStock: 92, stockout: 5, overstock: 3 },
  { category: 'Apparel', inStock: 87, stockout: 8, overstock: 5 },
  { category: 'Grocery', inStock: 95, stockout: 4, overstock: 1 },
  { category: 'Home', inStock: 89, stockout: 6, overstock: 5 },
  { category: 'Sports', inStock: 84, stockout: 10, overstock: 6 },
]

interface LowStockItem {
  sku: string
  product: string
  category: string
  stockLevel: number
  reorderPoint: number
  daysOfSupply: number
  reorderStatus: string
}

const lowStockAlerts: LowStockItem[] = [
  { sku: 'SKU-ELEC-001', product: 'Wireless Earbuds Pro', category: 'Electronics', stockLevel: 12, reorderPoint: 50, daysOfSupply: 2, reorderStatus: 'PO Created' },
  { sku: 'SKU-ELEC-018', product: 'USB-C Hub 7-in-1', category: 'Electronics', stockLevel: 8, reorderPoint: 35, daysOfSupply: 3, reorderStatus: 'Urgent' },
  { sku: 'SKU-APRL-042', product: 'Running Shoes V3', category: 'Apparel', stockLevel: 15, reorderPoint: 40, daysOfSupply: 4, reorderStatus: 'PO Created' },
  { sku: 'SKU-GROC-105', product: 'Organic Protein Bars (24pk)', category: 'Grocery', stockLevel: 22, reorderPoint: 80, daysOfSupply: 3, reorderStatus: 'Pending Approval' },
  { sku: 'SKU-HOME-033', product: 'Smart LED Bulb Kit', category: 'Home', stockLevel: 5, reorderPoint: 25, daysOfSupply: 1, reorderStatus: 'Urgent' },
  { sku: 'SKU-SPRT-019', product: 'Yoga Mat Premium', category: 'Sports', stockLevel: 18, reorderPoint: 30, daysOfSupply: 5, reorderStatus: 'Awaiting Supplier' },
  { sku: 'SKU-ELEC-055', product: 'Portable Charger 20K', category: 'Electronics', stockLevel: 9, reorderPoint: 45, daysOfSupply: 2, reorderStatus: 'PO Created' },
  { sku: 'SKU-HOME-071', product: 'Stainless Water Bottle', category: 'Home', stockLevel: 14, reorderPoint: 60, daysOfSupply: 3, reorderStatus: 'Pending Approval' },
]

function getStockLevelColor(daysOfSupply: number): string {
  if (daysOfSupply <= 2) return 'text-red-400'
  if (daysOfSupply <= 4) return 'text-amber-400'
  return 'text-green-400'
}

function getStockBgColor(daysOfSupply: number): string {
  if (daysOfSupply <= 2) return 'bg-red-900/20'
  if (daysOfSupply <= 4) return 'bg-amber-900/20'
  return 'bg-green-900/20'
}

const reorderStatusColors: Record<string, string> = {
  'Urgent': 'bg-red-900/30 text-red-400 border-red-800/50',
  'PO Created': 'bg-emerald-900/30 text-emerald-400 border-emerald-800/50',
  'Pending Approval': 'bg-yellow-900/30 text-yellow-400 border-yellow-800/50',
  'Awaiting Supplier': 'bg-blue-900/30 text-blue-400 border-blue-800/50',
}

export default function InventoryDashboard() {
  const totalValue = abcData.reduce((sum, d) => sum + d.value, 0)

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Inventory Dashboard</h2>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard title="Total SKUs" value="2,750" icon={Package} change="142 active categories" />
        <StatCard title="In-Stock Rate" value="91.4%" icon={CheckCircle} change="+1.8% vs last month" positive />
        <StatCard title="Inventory Value" value="$5.9M" icon={DollarSign} change="Across all warehouses" highlight />
        <StatCard title="Turnover Rate" value="8.2x" icon={RefreshCw} change="+0.6x vs last quarter" positive />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-2 gap-6">
        {/* ABC Classification Donut */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">ABC Classification</h3>
          <div className="flex items-center">
            <ResponsiveContainer width="55%" height={240}>
              <RPieChart>
                <Pie
                  data={abcData}
                  dataKey="value"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={90}
                  paddingAngle={3}
                >
                  {abcData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                  formatter={(value: number) => [`$${(value / 1000000).toFixed(2)}M`, 'Value']}
                />
              </RPieChart>
            </ResponsiveContainer>
            <div className="flex-1 space-y-4">
              {abcData.map((item) => (
                <div key={item.name}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full" style={{ background: item.color }} />
                      <span className="text-sm font-medium text-gray-300">{item.name}</span>
                    </div>
                    <span className="text-sm font-bold text-white">{item.pctValue}%</span>
                  </div>
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span>{item.count} SKUs</span>
                    <span>${(item.value / 1000000).toFixed(2)}M</span>
                  </div>
                  <div className="mt-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${(item.count / 2750) * 100}%`, background: item.color }}
                    />
                  </div>
                  <div className="text-[10px] text-gray-600 mt-0.5">
                    {((item.count / 2750) * 100).toFixed(1)}% of total SKUs
                  </div>
                </div>
              ))}
              <div className="pt-2 border-t border-gray-800 text-xs text-gray-500">
                Total inventory: ${(totalValue / 1000000).toFixed(1)}M
              </div>
            </div>
          </div>
        </div>

        {/* Stock Health by Category */}
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Stock Health by Category</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={stockHealthData} margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
              <XAxis dataKey="category" stroke="#6b7280" fontSize={12} />
              <YAxis stroke="#6b7280" fontSize={12} tickFormatter={(v) => `${v}%`} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(value: number, name: string) => {
                  const labels: Record<string, string> = { inStock: 'In Stock', stockout: 'Stockout', overstock: 'Overstock' }
                  return [`${value}%`, labels[name] || name]
                }}
              />
              <Legend
                formatter={(value: string) => {
                  const labels: Record<string, string> = { inStock: 'In Stock', stockout: 'Stockout', overstock: 'Overstock' }
                  return <span className="text-xs text-gray-400">{labels[value] || value}</span>
                }}
              />
              <Bar dataKey="inStock" stackId="health" fill="#10b981" radius={[0, 0, 0, 0]} />
              <Bar dataKey="stockout" stackId="health" fill="#ef4444" />
              <Bar dataKey="overstock" stackId="health" fill="#f59e0b" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Low Stock Alerts Table */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-medium text-gray-400">Low Stock Alerts</h3>
          </div>
          <span className="text-xs text-gray-500">{lowStockAlerts.length} items below reorder point</span>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 text-left">SKU</th>
              <th className="px-6 py-3 text-left">Product</th>
              <th className="px-6 py-3 text-right">Stock Level</th>
              <th className="px-6 py-3 text-right">Reorder Pt</th>
              <th className="px-6 py-3 text-center">Days of Supply</th>
              <th className="px-6 py-3 text-center">Reorder Status</th>
            </tr>
          </thead>
          <tbody>
            {lowStockAlerts.map((item) => (
              <tr key={item.sku} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-6 py-3">
                  <span className="font-medium text-emerald-400">{item.sku}</span>
                </td>
                <td className="px-6 py-3">
                  <div className="text-gray-300 text-sm">{item.product}</div>
                  <div className="text-xs text-gray-500">{item.category}</div>
                </td>
                <td className="px-6 py-3 text-right">
                  <span className={`font-medium ${getStockLevelColor(item.daysOfSupply)}`}>{item.stockLevel}</span>
                </td>
                <td className="px-6 py-3 text-right text-gray-400 text-sm">{item.reorderPoint}</td>
                <td className="px-6 py-3 text-center">
                  <span className={`inline-flex items-center justify-center w-8 h-8 rounded-lg text-sm font-bold ${getStockLevelColor(item.daysOfSupply)} ${getStockBgColor(item.daysOfSupply)}`}>
                    {item.daysOfSupply}
                  </span>
                </td>
                <td className="px-6 py-3 text-center">
                  <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border ${reorderStatusColors[item.reorderStatus]}`}>
                    {item.reorderStatus}
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

function StatCard({ title, value, icon: Icon, change, positive, highlight }: {
  title: string; value: string; icon: React.ElementType; change: string; positive?: boolean; highlight?: boolean
}) {
  return (
    <div className={`bg-gray-900 rounded-xl p-5 border ${highlight ? 'border-emerald-800/50' : 'border-gray-800'}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className="w-5 h-5 text-gray-500" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className={`text-sm mt-1 ${positive ? 'text-green-400' : 'text-gray-400'}`}>{change}</div>
    </div>
  )
}
