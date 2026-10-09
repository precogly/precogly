import { describe, it, expect } from 'vitest'
import { STRIDE_SUMMARY_SECTION_ID, getSectionsForType, isStrideSummaryVisible } from '../reportConfig'

describe('isStrideSummaryVisible', () => {
  it('is true when the methodologies include STRIDE, whatever the case', () => {
    expect(isStrideSummaryVisible(['STRIDE'])).toBe(true)
    expect(isStrideSummaryVisible(['PASTA', 'STRIDE'])).toBe(true)
    expect(isStrideSummaryVisible(['stride'])).toBe(true)
  })

  it('is false for a model without STRIDE, or with no methodologies', () => {
    expect(isStrideSummaryVisible(['PASTA'])).toBe(false)
    expect(isStrideSummaryVisible(['LINDDUN', 'attack-tree'])).toBe(false)
    expect(isStrideSummaryVisible([])).toBe(false)
    expect(isStrideSummaryVisible(null)).toBe(false)
    expect(isStrideSummaryVisible(undefined)).toBe(false)
  })
})

describe('getSectionsForType', () => {
  it('keeps the STRIDE summary for a STRIDE model and drops it otherwise', () => {
    const ids = (methodologies: string[]) =>
      getSectionsForType('full', { methodologies }).map((section) => section.id)
    expect(ids(['STRIDE'])).toContain(STRIDE_SUMMARY_SECTION_ID)
    expect(ids(['PASTA'])).not.toContain(STRIDE_SUMMARY_SECTION_ID)
  })

  it('has no inherited section and has the review, objectives and unattached sections', () => {
    for (const reportType of ['executive', 'technical', 'compliance', 'full'] as const) {
      const ids = getSectionsForType(reportType).map((section) => section.id)
      expect(ids).not.toContain('inherited')
      expect(ids).toContain('review')
      expect(ids).toContain('businessObjectives')
    }
    expect(getSectionsForType('full').map((section) => section.id)).toContain('unattached')
  })
})
