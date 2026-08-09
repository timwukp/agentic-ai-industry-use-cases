import { Droplets, Gauge, Coins, DollarSign, TrendingUp } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useLocale } from '../../i18n/LocaleContext'
import { useApi } from '../../lib/api'
import type { FactorEntry, SignalsResponse } from './types'
import { Card, DerivedBadge, ErrorPane, LiveBadge, LoadingPane, fmtSigned } from './widgets'

const MACRO_ICONS: Record<string, LucideIcon> = {
  DCOILWTICO: Droplets,
  DCOILBRENTEU: Droplets,
  VIXCLS: Gauge,
  DTWEXBGS: DollarSign,
  T10YIE: TrendingUp,
  CPIAUCSL: TrendingUp,
}

/** loading in [-1,+1] → red (negative/de-escalating) to green bar position */
function loadingColor(loading: number): string {
  if (loading > 0.15) return 'bg-red-500' // rising intensity = risk-red
  if (loading < -0.15) return 'bg-green-500'
  return 'bg-slate-500'
}

export default function SignalsSection() {
  const { t } = useLocale()
  const { data, loading, error, reload } = useApi<SignalsResponse>(
    '/api/finance/signals',
  )

  if (loading) return <LoadingPane label={t('finance.loadingSignals')} />
  if (error || !data) {
    return (
      <Card title={t('finance.signalsHeading')}>
        <ErrorPane message={error ?? t('finance.noSignalsData')} onRetry={reload} />
      </Card>
    )
  }

  const factors: FactorEntry[] = Object.values(data.factors.factors ?? {})
  const hotspots = data.hotspots.hotspots ?? []
  const macro = Object.values(data.macro.series ?? {})
  const gold = data.gold

  return (
    <div className="space-y-4 @container" data-section="signals">
      {/* Macro tiles: official data, live badge */}
      <Card
        title={t('finance.macroHeading')}
        action={
          !data.macro.error &&
          data.macro.provider && (
            <LiveBadge
              provider={data.macro.provider}
              fetchedAt={data.macro.fetched_at ?? ''}
              delay={data.macro.delay ?? ''}
            />
          )
        }
      >
        {data.macro.error ? (
          <ErrorPane message={data.macro.error} />
        ) : (
          <div className="p-4 @lg:p-5 grid grid-cols-2 @lg:grid-cols-3 @3xl:grid-cols-7 gap-2 @lg:gap-3">
            {macro.map((m) => {
              const Icon = MACRO_ICONS[m.series] ?? TrendingUp
              return (
                <div
                  key={m.series}
                  className="bg-slate-950 rounded-lg px-3 py-2.5 border border-slate-800"
                  data-kpi={`macro-${m.series}`}
                >
                  <div className="flex items-center gap-1.5 text-[11px] text-slate-400 mb-1">
                    <Icon className="w-3 h-3" />
                    {m.label}
                  </div>
                  <div className="text-sm font-bold text-white tabular-nums" data-kpi-value>
                    {m.value.toLocaleString('en-US', { maximumFractionDigits: 2 })}
                  </div>
                  <div className="text-[10px] text-slate-500">{m.as_of_date}</div>
                </div>
              )
            })}
            {gold?.value !== undefined && (
              <div
                className="bg-slate-950 rounded-lg px-3 py-2.5 border border-slate-800"
                data-kpi="macro-XAUUSD"
              >
                <div className="flex items-center gap-1.5 text-[11px] text-slate-400 mb-1">
                  <Coins className="w-3 h-3" />
                  {gold.label ?? 'Gold'}
                </div>
                <div className="text-sm font-bold text-white tabular-nums" data-kpi-value>
                  {gold.value.toLocaleString('en-US', { maximumFractionDigits: 2 })}
                </div>
                {gold.change_pct !== undefined && (
                  <div className="text-[10px] text-slate-500">
                    {fmtSigned(gold.change_pct, '%')}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </Card>

      {/* Factor heat strip + hotspots: derived, hypothesis-grade */}
      <Card
        title={t('finance.factorsHeading')}
        action={<DerivedBadge fetchedAt={data.factors.fetched_at} />}
      >
        {data.factors.error ? (
          <ErrorPane message={data.factors.error} />
        ) : (
          <div className="p-4 @lg:p-5 space-y-4">
            <p className="text-xs text-slate-500">{t('finance.derivedDisclaimer')}</p>
            <div className="grid grid-cols-1 @lg:grid-cols-2 @3xl:grid-cols-3 gap-x-6 gap-y-2.5">
              {factors
                .sort((a, b) => Math.abs(b.loading) - Math.abs(a.loading))
                .map((f) => (
                  <div key={f.factor} className="flex items-center gap-3" data-factor={f.factor}>
                    <span className="text-xs text-slate-400 w-36 shrink-0 truncate">
                      {f.label}
                    </span>
                    {/* centered diverging bar: left = de-escalating, right = intensifying */}
                    <div className="relative flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div className="absolute left-1/2 top-0 bottom-0 w-px bg-slate-600" />
                      <div
                        className={`absolute top-0 bottom-0 ${loadingColor(f.loading)} rounded-full`}
                        style={{
                          left: f.loading >= 0 ? '50%' : `${50 + f.loading * 50}%`,
                          width: `${Math.abs(f.loading) * 50}%`,
                        }}
                      />
                    </div>
                    <span className="text-xs tabular-nums text-slate-300 w-12 text-right">
                      {fmtSigned(f.loading)}
                    </span>
                    <span className="text-[10px] text-slate-500 w-8 text-right">
                      {f.event_count}
                    </span>
                  </div>
                ))}
            </div>

            {hotspots.length > 0 && (
              <div className="pt-3 border-t border-slate-800 space-y-2">
                <div className="text-xs font-medium text-slate-400">
                  {t('finance.hotspotsHeading')}
                </div>
                {hotspots.slice(0, 4).map(
                  (h) =>
                    h.top_headlines[0] && (
                      <div key={h.factor} className="flex items-baseline gap-2 text-xs">
                        <span className="shrink-0 px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          {h.label}
                        </span>
                        <span className="text-slate-400 truncate">
                          {h.top_headlines[0]}
                        </span>
                      </div>
                    ),
                )}
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
