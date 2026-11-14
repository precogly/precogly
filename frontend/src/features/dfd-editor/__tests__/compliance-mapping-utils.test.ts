import { describe, expect, it } from 'vitest'
import type { InstanceCountermeasureStandard } from '@/features/compliance/api/compliance'
import { mergeComplianceMappings } from '../components/threat-analysis/compliance-mapping-utils'
import type { ComplianceStandardMapping } from '../types/threat-analysis'

function known(overrides: Partial<ComplianceStandardMapping>): ComplianceStandardMapping {
  return {
    id: 1,
    requirement: 100,
    frameworkName: 'PCI-DSS',
    frameworkSlug: 'pci-dss',
    sectionCode: '3.4',
    requirementDescription: 'Render PAN unreadable',
    sufficiency: 'partial',
    ...overrides,
  }
}

function instance(overrides: Partial<InstanceCountermeasureStandard>): InstanceCountermeasureStandard {
  return {
    id: 50,
    countermeasure: 7,
    requirement: 100,
    frameworkName: 'PCI-DSS',
    frameworkSlug: 'pci-dss',
    sectionCode: '3.4',
    requirementDescription: 'Render PAN unreadable',
    sufficiency: 'full',
    createdAt: '',
    updatedAt: '',
    ...overrides,
  }
}

describe('mergeComplianceMappings', () => {
  it('collapses the same requirement in both lists to one editable instance row', () => {
    const merged = mergeComplianceMappings([known({ id: 9, requirement: 100 })], [instance({ id: 50, requirement: 100 })])
    expect(merged).toHaveLength(1)
    expect(merged[0]).toMatchObject({ id: 50, requirementId: 100, source: 'instance', sufficiency: 'full' })
  })

  it('keeps a requirement only in the known list as one read-only library row', () => {
    const merged = mergeComplianceMappings(
      [known({ id: 9, requirement: 100 }), known({ id: 10, requirement: 200, sectionCode: '8.3' })],
      [instance({ id: 50, requirement: 100 })]
    )
    expect(merged).toHaveLength(2)
    const libraryOnly = merged.find((m) => m.requirementId === 200)
    expect(libraryOnly).toMatchObject({ source: 'library', sectionCode: '8.3' })
    expect(libraryOnly?.id).toBeUndefined()
  })

  it('shows no library rows for a custom countermeasure whose known list equals its instance list', () => {
    const merged = mergeComplianceMappings(
      [known({ id: 50, requirement: 100 }), known({ id: 51, requirement: 200 })],
      [instance({ id: 50, requirement: 100 }), instance({ id: 51, requirement: 200 })]
    )
    expect(merged).toHaveLength(2)
    expect(merged.every((m) => m.source === 'instance')).toBe(true)
  })

  it('shows an instance mapping without a requirement once as a snapshot and never as a library row', () => {
    const merged = mergeComplianceMappings(
      [known({ id: 60, requirement: null, frameworkName: 'Retired' })],
      [instance({ id: 60, requirement: null as unknown as number, frameworkName: 'Retired' })]
    )
    expect(merged).toHaveLength(1)
    expect(merged[0]).toMatchObject({ id: 60, requirementId: null, source: 'snapshot' })
  })

  it('treats a known entry with no requirement field as unusable rather than a library row', () => {
    const merged = mergeComplianceMappings([known({ id: 9, requirement: undefined })], [])
    expect(merged).toHaveLength(0)
  })
})
