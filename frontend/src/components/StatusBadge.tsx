type Tone = 'ok' | 'warn' | 'neutral'

const toneClass: Record<Tone, string> = {
  ok: 'bg-emerald-50 text-emerald-800 ring-emerald-600/20',
  warn: 'bg-amber-50 text-amber-800 ring-amber-600/20',
  neutral: 'bg-slate-100 text-slate-700 ring-slate-500/20',
}

/**
 * Renders a label as plain React text. Never pass HTML here expecting it to render:
 * all strings are escaped by React (docs/security-design.md §14).
 */
export function StatusBadge({ label, tone }: { label: string; tone: Tone }) {
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset ${toneClass[tone]}`}>
      {label}
    </span>
  )
}
