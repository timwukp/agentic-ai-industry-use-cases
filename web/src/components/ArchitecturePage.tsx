import { ExternalLink } from 'lucide-react'
import { useLocale } from '../i18n/LocaleContext'
import architectureSvg from '../assets/architecture.svg'
import requestFlowSvg from '../assets/request-flow.svg'

const README_URL =
  'https://github.com/timwukp/agentic-ai-industry-use-cases#architecture'

/** Static introduction to the solution architecture: the two animated SVGs
 * from docs/ (SMIL runs inside <img>). The assets are byte-copies of the
 * generated originals — tests/unit/architectureAssets.test.ts enforces it. */
export default function ArchitecturePage() {
  const { t } = useLocale()
  return (
    <div className="h-full overflow-y-auto">
      <div className="p-4 lg:p-6 space-y-6 max-w-5xl mx-auto">
        <div>
          <h2 className="text-lg lg:text-xl font-bold text-white">
            {t('architecture.title')}
          </h2>
          <p className="mt-2 text-sm text-slate-400">{t('architecture.intro')}</p>
        </div>

        <section className="space-y-2">
          <h3 className="text-sm font-semibold text-white">
            {t('architecture.system')}
          </h3>
          {/* frame matches the SVGs' own #0f172a background (slate-900 family) */}
          <figure className="rounded-lg border border-slate-800 bg-slate-900 overflow-hidden">
            <img
              src={architectureSvg}
              alt={t('architecture.system')}
              className="w-full h-auto"
              loading="lazy"
            />
            <figcaption className="px-4 py-3 text-xs text-slate-500 border-t border-slate-800">
              {t('architecture.systemCaption')}
            </figcaption>
          </figure>
        </section>

        <section className="space-y-2">
          <h3 className="text-sm font-semibold text-white">
            {t('architecture.flow')}
          </h3>
          <figure className="rounded-lg border border-slate-800 bg-slate-900 overflow-hidden">
            <img
              src={requestFlowSvg}
              alt={t('architecture.flow')}
              className="w-full h-auto"
              loading="lazy"
            />
            <figcaption className="px-4 py-3 text-xs text-slate-500 border-t border-slate-800">
              {t('architecture.flowCaption')}
            </figcaption>
          </figure>
        </section>

        <a
          href={README_URL}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300"
        >
          {t('architecture.readme')}
          <ExternalLink className="w-3.5 h-3.5" />
        </a>
      </div>
    </div>
  )
}
