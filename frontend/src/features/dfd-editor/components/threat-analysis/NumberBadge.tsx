/** The small monospace number of a threat or control: `T7`, `C3` (plan 11.3). */

import { cn } from '@/lib/utils'

interface NumberBadgeProps {
  number: string | undefined | null
  className?: string
  /** Clickable, for "Also on" and linked-threat lists. */
  onClick?: () => void
  title?: string
}

export function NumberBadge({ number, className, onClick, title }: NumberBadgeProps) {
  if (!number) return null
  const classes = cn(
    'inline-flex shrink-0 items-center rounded border border-slate-300 bg-slate-50 px-1 font-mono text-[10px] leading-4 text-slate-700',
    onClick && 'cursor-pointer hover:bg-slate-200',
    className
  )
  if (onClick) {
    return (
      <button type="button" className={classes} onClick={onClick} title={title} data-number={number}>
        {number}
      </button>
    )
  }
  return (
    <span className={classes} title={title} data-number={number}>
      {number}
    </span>
  )
}
