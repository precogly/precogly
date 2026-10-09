/**
 * Each control once, with every scenario it is linked to, for the report's
 * countermeasure detail table, the Word export and the pentest scope.
 */

import type { ReportThreat } from '@/features/reports/types/report'

/** A control once, with every scenario it is linked to (a control can mitigate several, plan 11.3). */
export interface CountermeasureDetailRow {
  id: number
  displayNumber: string
  number: number
  countermeasureName: string
  status: string
  priority: string
  controlFunctions: string[]
  scope: string[]
  implementedByParty: string
  source: string
  assignedOwnerEmail: string | null
  complianceStandards: string[]
  /** `T7` of each linked scenario, in threat order. */
  threatNumbers: string[]
}

/** Every control linked to a threat, once, ordered by its number. */
export function buildCountermeasureDetailRows(threats: readonly ReportThreat[]): CountermeasureDetailRow[] {
  const rowsById = new Map<number, CountermeasureDetailRow>()
  for (const threat of threats) {
    for (const countermeasure of threat.countermeasures) {
      const existing = rowsById.get(countermeasure.id)
      if (existing) {
        if (!existing.threatNumbers.includes(threat.displayNumber)) existing.threatNumbers.push(threat.displayNumber)
        continue
      }
      rowsById.set(countermeasure.id, {
        id: countermeasure.id,
        displayNumber: countermeasure.displayNumber,
        number: countermeasure.number,
        countermeasureName: countermeasure.countermeasureName,
        status: countermeasure.status,
        priority: countermeasure.priority,
        controlFunctions: countermeasure.controlFunctions ?? [],
        scope: countermeasure.scope ?? [],
        implementedByParty: countermeasure.implementedByParty ?? '',
        source: countermeasure.source ?? '',
        assignedOwnerEmail: countermeasure.assignedOwnerEmail,
        complianceStandards: (countermeasure.complianceStandards ?? []).map(
          (standard) => `${standard.frameworkName} ${standard.sectionCode}`
        ),
        threatNumbers: [threat.displayNumber],
      })
    }
  }
  return [...rowsById.values()].sort((left, right) => left.number - right.number)
}
