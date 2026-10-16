/**
 * The URL slugs of the threat model page's tabs: one URL per sub-screen, so
 * reload keeps the tab and Back and Forward move between tabs.
 */

export const THREAT_MODEL_TABS = ['overview', 'threat-analysis', 'risk-analysis', 'pentests', 'reports'] as const
export type ThreatModelTab = (typeof THREAT_MODEL_TABS)[number]

/** The shared (magic link) view shows only these two. */
export const SHARED_VIEW_TABS = ['overview', 'threat-analysis'] as const
export type SharedViewTab = (typeof SHARED_VIEW_TABS)[number]

export const DEFAULT_MODEL_TAB = 'overview'

/** The tab a URL segment names, or null when it names none (missing or unknown). */
export function tabFromSlug<Tab extends string>(slug: string | undefined, allowedTabs: readonly Tab[]): Tab | null {
  if (!slug) return null
  return (allowedTabs as readonly string[]).includes(slug) ? (slug as Tab) : null
}

/** The path of one tab of a threat model. */
export function threatModelTabPath(threatModelId: string | number, tab: ThreatModelTab): string {
  return `/threat-models/${threatModelId}/${tab}`
}

/** The views of the Threat Analysis tab, one URL each: `/threat-analysis/components` and so on. */
export const THREAT_ANALYSIS_VIEWS = ['components', 'use-cases', 'table'] as const
export type ThreatAnalysisView = (typeof THREAT_ANALYSIS_VIEWS)[number]

export const DEFAULT_THREAT_ANALYSIS_VIEW: ThreatAnalysisView = 'components'

/** The path of one view of the Threat Analysis tab. */
export function threatAnalysisViewPath(threatModelId: string | number, view: ThreatAnalysisView): string {
  return `${threatModelTabPath(threatModelId, 'threat-analysis')}/${view}`
}
