import { describe, it, expect } from 'vitest'
import {
  SHARED_VIEW_TABS,
  THREAT_ANALYSIS_VIEWS,
  THREAT_MODEL_TABS,
  tabFromSlug,
  threatAnalysisViewPath,
  threatModelTabPath,
} from '../lib/model-tabs'

describe('threat model tab slugs', () => {
  it('reads every known slug', () => {
    for (const tab of THREAT_MODEL_TABS) {
      expect(tabFromSlug(tab, THREAT_MODEL_TABS)).toBe(tab)
    }
  })

  it('gives null for a missing or unknown slug', () => {
    expect(tabFromSlug(undefined, THREAT_MODEL_TABS)).toBeNull()
    expect(tabFromSlug('', THREAT_MODEL_TABS)).toBeNull()
    expect(tabFromSlug('threats', THREAT_MODEL_TABS)).toBeNull()
    expect(tabFromSlug('diagrams', THREAT_MODEL_TABS)).toBeNull()
  })

  it('limits the shared view to overview and threat analysis', () => {
    expect(tabFromSlug('threat-analysis', SHARED_VIEW_TABS)).toBe('threat-analysis')
    expect(tabFromSlug('reports', SHARED_VIEW_TABS)).toBeNull()
  })

  it('builds the path of a tab', () => {
    expect(threatModelTabPath(3, 'threat-analysis')).toBe('/threat-models/3/threat-analysis')
    expect(threatModelTabPath('7', 'overview')).toBe('/threat-models/7/overview')
  })

  it('reads the threat analysis views and builds their paths', () => {
    expect(tabFromSlug('use-cases', THREAT_ANALYSIS_VIEWS)).toBe('use-cases')
    expect(tabFromSlug('usecase', THREAT_ANALYSIS_VIEWS)).toBeNull()
    expect(threatAnalysisViewPath(3, 'table')).toBe('/threat-models/3/threat-analysis/table')
  })
})
