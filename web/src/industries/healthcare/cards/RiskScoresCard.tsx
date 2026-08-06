import { useState } from 'react'
import { useApi } from '../../../lib/api'
import { useLocale } from '../../../i18n/LocaleContext'
import { Card, ErrorPane, LoadingPane } from '../../finance/widgets'
import { AskAgentButton, StatusPill, type PillTone } from '../widgets'
import type { RiskScoreResponse } from '../types'

type RiskType = 'cardiovascular' | 'diabetes' | 'falls'

const SEGMENTS: Array<{ type: RiskType; labelKey: string }> = [
  { type: 'cardiovascular', labelKey: 'healthcare.segAscvd' },
  { type: 'diabetes', labelKey: 'healthcare.segDiabetes' },
  { type: 'falls', labelKey: 'healthcare.segFalls' },
]

function interpretationTone(interpretation?: string): PillTone {
  const s = (interpretation ?? '').toUpperCase()
  if (s.includes('HIGH')) return 'red'
  if (s.includes('MODERATE') || s.includes('INTERMEDIATE') || s.includes('BORDERLINE'))
    return 'amber'
  if (s.includes('LOW')) return 'green'
  return 'slate'
}

export default function RiskScoresCard({ patientId }: { patientId: string }) {
  const { t } = useLocale()
  const [riskType, setRiskType] = useState<RiskType>('cardiovascular')
  const { data, loading, error, reload } = useApi<RiskScoreResponse>(
    `/api/healthcare/risk?patientId=${encodeURIComponent(patientId)}&type=${riskType}`,
  )

  const headerAction = (
    <div className="flex items-center gap-1">
      <AskAgentButton
        prompt={`Explain this ${riskType} risk score for ${patientId} and what to do about it`}
      />
      <div className="flex rounded-lg border border-slate-700 overflow-hidden text-xs">
        {SEGMENTS.map((seg) => (
          <button
            key={seg.type}
            type="button"
            onClick={() => setRiskType(seg.type)}
            className={`px-3 py-1.5 transition-colors ${
              riskType === seg.type
                ? 'bg-slate-700 text-white'
                : 'bg-slate-800/60 text-slate-400 hover:text-slate-200'
            }`}
          >
            {t(seg.labelKey)}
          </button>
        ))}
      </div>
    </div>
  )

  // While a new risk type loads, keep the previous result on screen (dimmed)
  // instead of unmounting — useApi retains the prior data until fetch resolves.
  const showStale = loading && data != null

  return (
    <Card title={t('healthcare.riskScores')} action={headerAction}>
      {loading && !data ? (
        <LoadingPane label={t('healthcare.calculatingRisk')} />
      ) : error || (!showStale && (!data || data.error)) ? (
        <ErrorPane
          message={error ?? data?.error ?? t('healthcare.noRiskData')}
          onRetry={reload}
        />
      ) : (
        <div
          className={`p-4 @lg:p-5 space-y-3 transition-opacity ${showStale ? 'opacity-50' : ''}`}
        >
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-baseline gap-2">
              <span className="text-4xl font-bold text-white tabular-nums">
                {data?.score ?? '—'}
              </span>
              <span className="text-xs text-slate-500">{data?.unit ?? ''}</span>
            </div>
            {data?.risk_category && (
              <StatusPill
                tone={interpretationTone(data.interpretation)}
                label={data.risk_category}
              />
            )}
          </div>

          {data?.interpretation && (
            <p className="text-sm text-slate-300">{data.interpretation}</p>
          )}

          {(data?.recommendations ?? []).length > 0 && (
            <ul className="space-y-1.5 pt-1">
              {(data?.recommendations ?? []).slice(0, 3).map((rec) => (
                <li key={rec} className="flex gap-2 text-xs text-slate-400">
                  <span className="text-rose-400 shrink-0">•</span>
                  {rec}
                </li>
              ))}
            </ul>
          )}

          {data?.risk_model && (
            <p className="text-[11px] text-slate-600 pt-1">{data.risk_model}</p>
          )}
        </div>
      )}
    </Card>
  )
}
