import { Activity, CheckCircle2, FlaskConical, TrendingDown } from 'lucide-react'
import { useLocale } from '../../i18n/LocaleContext'
import { useApi } from '../../lib/api'
import type { PrismResponse } from './types'
import { Card, ErrorPane, LoadingPane, fmtSigned } from './widgets'

const STATE_COLORS: Record<string, string> = {
  stress: 'bg-red-500',
  neutral: 'bg-slate-400',
  'risk-on': 'bg-green-500',
}

/** Model-output badge: PRISM results are statistical estimates. */
function ModelBadge({ version, fetchedAt }: { version?: string; fetchedAt?: string }) {
  const { t } = useLocale()
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-sky-950/50 border border-sky-800/50 text-[11px] text-sky-300"
      data-model-badge
    >
      <Activity className="w-3 h-3" />
      {t('widgets.model')}
      {version && ` · ${version}`}
      {fetchedAt && ` · ${new Date(fetchedAt).toLocaleDateString()}`}
    </span>
  )
}

export default function PrismSection() {
  const { t } = useLocale()
  const { data, loading, error, reload } = useApi<PrismResponse>('/api/finance/prism')

  if (loading) return <LoadingPane label={t('finance.loadingPrism')} />
  if (error || !data) {
    return (
      <Card title={t('finance.prismHeading')}>
        <ErrorPane message={error ?? t('finance.noPrismData')} onRetry={reload} />
      </Card>
    )
  }

  const regime = data.regime
  const regularities = data.regularities
  const confirmed = regularities.confirmed ?? []
  const stateProbs = Object.entries(regime.state_probs ?? {})

  return (
    <div className="space-y-4 @container" data-section="prism">
      <Card
        title={t('finance.regimeHeading')}
        action={<ModelBadge version={regime.prism_version} fetchedAt={regime.fetched_at} />}
      >
        {regime.error ? (
          <ErrorPane message={regime.error} />
        ) : (
          <div className="p-4 @lg:p-5 space-y-3">
            <div className="flex items-baseline gap-3">
              <span className="text-2xl font-bold text-white capitalize" data-kpi="regime-state" data-kpi-value>
                {regime.current_state}
              </span>
              <span className="text-xs text-slate-500">
                {t('finance.regimeSub')}
              </span>
            </div>
            {/* probability ribbon */}
            {stateProbs.length > 0 && (
              <>
                <div className="flex h-3 rounded-full overflow-hidden">
                  {stateProbs.map(([state, p]) => (
                    <div
                      key={state}
                      className={STATE_COLORS[state] ?? 'bg-slate-500'}
                      style={{ width: `${p * 100}%` }}
                      title={`${state}: ${(p * 100).toFixed(1)}%`}
                    />
                  ))}
                </div>
                <div className="flex justify-between text-[11px] text-slate-500">
                  {stateProbs.map(([state, p]) => (
                    <span key={state} className="capitalize">
                      {state} {(p * 100).toFixed(0)}%
                    </span>
                  ))}
                </div>
              </>
            )}
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 @3xl:grid-cols-2 gap-3 @lg:gap-4">
        <Card title={t('finance.regularitiesHeading')}>
          {regularities.error ? (
            <ErrorPane message={regularities.error} />
          ) : (
            <div className="p-4 @lg:p-5 space-y-3">
              <div className="flex items-center gap-4 text-xs">
                <span className="inline-flex items-center gap-1 text-green-300">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  {confirmed.length} {t('finance.confirmedLabel')}
                </span>
                <span className="inline-flex items-center gap-1 text-violet-300">
                  <FlaskConical className="w-3.5 h-3.5" />
                  {regularities.hypothesis_count ?? 0} {t('finance.hypothesisLabel')}
                </span>
              </div>
              {confirmed.length === 0 ? (
                <p className="text-xs text-slate-500">{t('finance.noConfirmedYet')}</p>
              ) : (
                confirmed.map((e) => (
                  <div
                    key={`${e.source}-${e.target}-${e.horizon}`}
                    className="flex items-center justify-between text-xs bg-slate-950 rounded-lg px-3 py-2 border border-slate-800"
                  >
                    <span className="text-slate-300">
                      {e.source} → {e.target}
                    </span>
                    <span className="text-slate-500">
                      h={e.horizon}d · q={e.q_value?.toFixed(3)}
                    </span>
                  </div>
                ))
              )}
              {regularities.factor_causality === 'insufficient_data' && (
                <p className="text-[11px] text-slate-500">
                  {t('finance.factorDataAccruing')} ({regularities.days_available}/
                  {regularities.days_needed})
                </p>
              )}
            </div>
          )}
        </Card>

        <Card title={t('finance.tailRiskHeading')}>
          <div className="p-4 @lg:p-5 space-y-3">
            {Object.entries(data.tails).map(([asset, tr]) =>
              tr.error ? (
                <p key={asset} className="text-xs text-slate-500">
                  {asset}: {tr.error}
                </p>
              ) : (
                <div key={asset} className="space-y-1" data-kpi={`tail-${asset}`}>
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <TrendingDown className="w-3.5 h-3.5" />
                    {asset}
                    {tr.valid === false && (
                      <span className="text-amber-400">({t('finance.lowSample')})</span>
                    )}
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <div className="bg-slate-950 rounded px-2 py-1.5 border border-slate-800">
                      <div className="text-slate-500">VaR 99%</div>
                      <div className="text-white tabular-nums" data-kpi-value>
                        {tr.var_99 !== undefined ? fmtSigned(-Math.abs(tr.var_99) * 100) + '%' : '—'}
                      </div>
                    </div>
                    <div className="bg-slate-950 rounded px-2 py-1.5 border border-slate-800">
                      <div className="text-slate-500">ES 99%</div>
                      <div className="text-white tabular-nums">
                        {tr.es_99 !== undefined ? fmtSigned(-Math.abs(tr.es_99) * 100) + '%' : '—'}
                      </div>
                    </div>
                    <div className="bg-slate-950 rounded px-2 py-1.5 border border-slate-800">
                      <div className="text-slate-500">ξ (tail)</div>
                      <div className="text-white tabular-nums">
                        {tr.xi !== undefined ? tr.xi.toFixed(2) : '—'}
                      </div>
                    </div>
                  </div>
                </div>
              ),
            )}
            <p className="text-[11px] text-slate-500">{t('finance.prismDisclaimer')}</p>
          </div>
        </Card>
      </div>
    </div>
  )
}
