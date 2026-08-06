/** Language selector — a native <select> behind a globe icon.
 *
 * Native on purpose: sixteen options get keyboard, screen-reader and mobile
 * support for free, and a popover would be the only one in the app. Option
 * text is each language's endonym (ไทย, हिन्दी), which needs no translation
 * and is findable by someone stuck in a language they cannot read.
 */
import { Languages } from 'lucide-react'
import { LOCALES, LOCALE_NAMES, type Locale } from '../i18n'
import { useLocale } from '../i18n/LocaleContext'

export default function LocalePicker({ className = '' }: { className?: string }) {
  const { locale, setLocale, t } = useLocale()
  return (
    <label
      className={`relative inline-flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 transition-colors cursor-pointer ${className}`}
      title={t('chrome.language')}
    >
      <Languages className="w-4 h-4 shrink-0 pointer-events-none" />
      <select
        data-testid="locale-picker"
        aria-label={t('chrome.language')}
        value={locale}
        onChange={(e) => setLocale(e.target.value as Locale)}
        // The select is the full-size hit target; the label supplies the look.
        className="absolute inset-0 w-full opacity-0 cursor-pointer"
      >
        {LOCALES.map((code) => (
          <option key={code} value={code}>
            {LOCALE_NAMES[code]}
          </option>
        ))}
      </select>
      <span className="text-xs pointer-events-none hidden sm:inline">
        {LOCALE_NAMES[locale]}
      </span>
    </label>
  )
}
