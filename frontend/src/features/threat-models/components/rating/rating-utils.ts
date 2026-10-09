/**
 * Display helpers for ratings, shared by RatingBadge, the reports and the
 * dashboard. Kept out of the component file so fast refresh works.
 */

import { RATING_LEVELS, type RatingLevel } from '@/types/risk'

/** Tailwind classes per level, `info` included. */
export const RATING_LEVEL_CLASSES: Record<RatingLevel, string> = {
  info: 'bg-slate-100 text-slate-700 border-slate-200',
  low: 'bg-green-100 text-green-700 border-green-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  critical: 'bg-red-100 text-red-700 border-red-200',
}

/** Hex colors per level, for charts and inline styles. */
export const RATING_LEVEL_COLORS: Record<RatingLevel, string> = {
  info: '#64748b',
  low: '#22c55e',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
}

const METHODOLOGY_LABELS: Record<string, string> = {
  'qualitative-matrix': 'Likelihood x Impact',
  'owasp-risk-rating': 'OWASP Risk Rating',
  fair: 'FAIR',
  'mozilla-rra': 'Mozilla RRA',
  manual: 'Level only',
}

export function ratingLevelLabel(level: string | null | undefined): string {
  const known = RATING_LEVELS.find((entry) => entry.value === level)
  return known?.label ?? (level ? level.charAt(0).toUpperCase() + level.slice(1) : 'Unrated')
}

export function methodologyLabel(methodology: string | null | undefined): string {
  if (!methodology) return ''
  return METHODOLOGY_LABELS[methodology] ?? methodology
}

/** "16 / 25" for the matrix, "5.8 / 9" for OWASP, nothing for a level-only rating. */
export function formatRatingScore(score: number | null | undefined, scoreScale?: string | null): string | null {
  if (score === null || score === undefined) return null
  const rounded = Number.isInteger(score) ? String(score) : score.toFixed(1)
  return scoreScale ? `${rounded} / ${scoreScale}` : rounded
}
