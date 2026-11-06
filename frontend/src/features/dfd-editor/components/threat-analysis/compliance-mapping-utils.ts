import type { InstanceCountermeasureStandard } from '@/features/compliance/api/compliance'
import type { ComplianceStandardMapping } from '../../types/threat-analysis'

export type MergedComplianceMappingSource = 'library' | 'instance' | 'snapshot'

export interface MergedComplianceMapping {
  /** The instance mapping row id; absent for a library-only row. */
  id?: number
  requirementId: number | null
  frameworkName: string
  sectionCode: string
  requirementDescription: string
  sufficiency: 'full' | 'partial'
  source: MergedComplianceMappingSource
}

/**
 * Merge the countermeasure's known mappings (the threat analysis payload, where
 * instance already wins over library per requirement) with the instance mappings
 * fetched live. Both lists are keyed by requirement id, so a mapping present in
 * both collapses to the one editable instance row. What stays tagged `library`
 * is exactly a mapping the library has and this countermeasure does not yet.
 * Instance mappings whose requirement was deleted show once as a read-only
 * `snapshot`; the known list's copies of those have no requirement and are skipped.
 */
export function mergeComplianceMappings(
  knownMappings: ComplianceStandardMapping[],
  instanceMappings: InstanceCountermeasureStandard[] | undefined
): MergedComplianceMapping[] {
  const mappingsByKey = new Map<number | string, MergedComplianceMapping>()

  for (const known of knownMappings) {
    if (known.requirement == null) continue
    mappingsByKey.set(known.requirement, {
      requirementId: known.requirement,
      frameworkName: known.frameworkName,
      sectionCode: known.sectionCode,
      requirementDescription: known.requirementDescription,
      sufficiency: known.sufficiency,
      source: 'library',
    })
  }

  for (const instance of instanceMappings ?? []) {
    if (instance.requirement != null) {
      mappingsByKey.set(instance.requirement, {
        id: instance.id,
        requirementId: instance.requirement,
        frameworkName: instance.frameworkName,
        sectionCode: instance.sectionCode,
        requirementDescription: instance.requirementDescription,
        sufficiency: instance.sufficiency,
        source: 'instance',
      })
    } else {
      mappingsByKey.set(`snapshot-${instance.id}`, {
        id: instance.id,
        requirementId: null,
        frameworkName: instance.frameworkName,
        sectionCode: instance.sectionCode,
        requirementDescription: instance.requirementDescription,
        sufficiency: instance.sufficiency,
        source: 'snapshot',
      })
    }
  }

  return Array.from(mappingsByKey.values())
}
