import { useApi } from '../../lib/api'
import type { Order, OrdersResponse } from './types'
import { Card, ErrorPane, LoadingPane, fmtUsd } from './widgets'

function StatusChip({ status }: { status: Order['status'] }) {
  const styles: Record<string, string> = {
    FILLED: 'bg-green-950/50 border-green-800/50 text-green-300',
    OPEN: 'bg-blue-950/50 border-blue-800/50 text-blue-300',
    CANCELLED: 'bg-slate-800 border-slate-700 text-slate-400',
    REJECTED: 'bg-red-950/50 border-red-800/50 text-red-300',
  }
  return (
    <span
      className={`inline-flex px-2 py-0.5 rounded-full text-[11px] font-medium border ${
        styles[status] ?? 'bg-slate-800 border-slate-700 text-slate-300'
      }`}
    >
      {status}
    </span>
  )
}

export default function OrdersSection() {
  const { data, loading, error, reload } = useApi<OrdersResponse>('/api/finance/orders')

  if (loading) return <LoadingPane label="Loading orders…" />
  if (error || !data) {
    return (
      <Card title="Recent Orders">
        <ErrorPane message={error ?? 'No order data'} onRetry={reload} />
      </Card>
    )
  }

  return (
    <Card title={`Recent Orders (last ${data.period_days} days)`}>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[520px]">
          <thead>
            <tr className="text-xs text-slate-500 border-b border-slate-800">
              <th className="px-5 py-3 text-left font-medium">Order</th>
              <th className="px-5 py-3 text-left font-medium">Symbol</th>
              <th className="px-5 py-3 text-left font-medium">Side</th>
              <th className="px-5 py-3 text-right font-medium">Qty</th>
              <th className="px-5 py-3 text-right font-medium">Fill Price</th>
              <th className="px-5 py-3 text-left font-medium">Status</th>
              <th className="px-5 py-3 text-right font-medium">Placed</th>
            </tr>
          </thead>
          <tbody>
            {data.orders.map((order) => (
              <tr
                key={order.orderId}
                className="border-b border-slate-800/50 last:border-0 hover:bg-slate-800/30"
              >
                <td className="px-5 py-3 text-xs text-slate-400 font-mono">
                  {order.orderId}
                </td>
                <td className="px-5 py-3 font-medium text-white">{order.symbol}</td>
                <td
                  className={`px-5 py-3 text-sm font-medium ${
                    order.side === 'BUY' ? 'text-green-400' : 'text-red-400'
                  }`}
                >
                  {order.side}
                </td>
                <td className="px-5 py-3 text-right text-slate-300 tabular-nums">
                  {order.quantity.toLocaleString()}
                </td>
                <td className="px-5 py-3 text-right text-slate-300 tabular-nums">
                  {order.fillPrice != null ? fmtUsd(order.fillPrice) : '—'}
                </td>
                <td className="px-5 py-3">
                  <StatusChip status={order.status} />
                </td>
                <td className="px-5 py-3 text-right text-xs text-slate-500 tabular-nums">
                  {new Date(order.createdAt).toLocaleDateString()}
                </td>
              </tr>
            ))}
            {data.orders.length === 0 && (
              <tr>
                <td colSpan={7} className="px-5 py-8 text-center text-sm text-slate-500">
                  No orders in this period — ask the agent to place one.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
