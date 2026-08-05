import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import type { ReactNode } from 'react'

/** Assistant message body, rendered as GitHub-flavored Markdown.
 *
 * Before this, chat text went through `whitespace-pre-wrap`, so nothing was
 * parsed — the agent's `|`-delimited tables arrived as raw pipes and `##`
 * headings showed their hashes. That is what made a market-overview answer
 * unreadable, and it is a rendering bug, not a prompting one: the model was
 * emitting correct Markdown all along.
 *
 * Every element is styled explicitly rather than via a typography plugin,
 * because the defaults assume a light background and a full-width article; this
 * renders inside a ~340px dark bubble. Tables get a horizontal scroller — six
 * numeric columns will not fit a phone, and letting them overflow silently
 * clipped the last column, which is usually the one being asked about.
 */
export default function Markdown({ children }: { children: string }) {
  return (
    <div className="md text-sm leading-relaxed break-words">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => <Heading level={1}>{children}</Heading>,
          h2: ({ children }) => <Heading level={2}>{children}</Heading>,
          h3: ({ children }) => <Heading level={3}>{children}</Heading>,
          h4: ({ children }) => <Heading level={3}>{children}</Heading>,

          p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,

          ul: ({ children }) => (
            <ul className="mb-2 last:mb-0 pl-4 space-y-0.5 list-disc marker:text-slate-500">
              {children}
            </ul>
          ),
          ol: ({ children }) => (
            <ol className="mb-2 last:mb-0 pl-4 space-y-0.5 list-decimal marker:text-slate-500">
              {children}
            </ol>
          ),
          li: ({ children }) => <li className="pl-0.5">{children}</li>,

          strong: ({ children }) => (
            <strong className="font-semibold text-white">{children}</strong>
          ),
          em: ({ children }) => <em className="italic text-slate-300">{children}</em>,

          a: ({ children, href }) => (
            <a
              href={href}
              target="_blank"
              rel="noreferrer noopener"
              className="text-blue-400 underline decoration-blue-400/40 hover:decoration-blue-400"
            >
              {children}
            </a>
          ),

          hr: () => <hr className="my-3 border-slate-700" />,

          blockquote: ({ children }) => (
            <blockquote className="mb-2 last:mb-0 pl-3 border-l-2 border-slate-600 text-slate-400">
              {children}
            </blockquote>
          ),

          // Tables are the whole point of this component.
          table: ({ children }) => (
            <div className="my-2 -mx-1 overflow-x-auto">
              <table className="w-full text-xs border-collapse">{children}</table>
            </div>
          ),
          thead: ({ children }) => (
            <thead className="text-slate-400">{children}</thead>
          ),
          tbody: ({ children }) => (
            <tbody className="divide-y divide-slate-800">{children}</tbody>
          ),
          tr: ({ children }) => <tr>{children}</tr>,
          th: ({ children }) => (
            <th className="px-2 py-1.5 text-left font-medium whitespace-nowrap border-b border-slate-700">
              {children}
            </th>
          ),
          // tabular-nums so figures line up column-wise; that is the reason to
          // put numbers in a table at all.
          td: ({ children }) => (
            <td className="px-2 py-1.5 align-top tabular-nums">{children}</td>
          ),

          code: ({ children, className }) => {
            // Fenced blocks carry a language class; inline code does not.
            const isBlock = typeof className === 'string' && className.includes('language-')
            if (isBlock) {
              return (
                <code className="block font-mono text-[11px] leading-snug whitespace-pre">
                  {children}
                </code>
              )
            }
            return (
              <code className="px-1 py-0.5 rounded bg-slate-900/80 border border-slate-700 font-mono text-[11px] text-slate-200">
                {children}
              </code>
            )
          },
          pre: ({ children }) => (
            <pre className="my-2 p-2.5 rounded-lg bg-slate-900/80 border border-slate-700 overflow-x-auto">
              {children}
            </pre>
          ),
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  )
}

/** Headings share one scale: an agent answer is a bubble, not a document, so h1
 *  and h2 collapsing to nearly the same size is intentional. */
function Heading({ level, children }: { level: 1 | 2 | 3; children: ReactNode }) {
  const size = level === 3 ? 'text-xs' : 'text-sm'
  return (
    <p className={`${size} font-semibold text-white mt-3 first:mt-0 mb-1.5`}>
      {children}
    </p>
  )
}
