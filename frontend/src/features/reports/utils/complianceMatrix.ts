/**
 * Pure helpers for the compliance matrix (screen, CSV and Word share them):
 * state labels, the "of the requirements in this pack" line, and the rows
 * shown when "Not covered" is hidden.
 */

import type { ComplianceMatrixFramework, ComplianceMatrixRow, ComplianceMatrixState } from '../types/report'

export const MATRIX_STATES: ComplianceMatrixState[] = ['satisfied', 'covered', 'partial_only', 'not_covered']

export const MATRIX_STATE_LABELS: Record<ComplianceMatrixState, string> = {
  satisfied: 'Satisfied',
  covered: 'Covered',
  partial_only: 'Partial only',
  not_covered: 'Not covered',
}

export const MATRIX_STATE_DESCRIPTIONS: Record<ComplianceMatrixState, string> = {
  satisfied: 'A countermeasure fully addresses it and is verified or platform.',
  covered: 'A countermeasure fully addresses it but is not in effect yet.',
  partial_only: 'Only countermeasures that partly address it are mapped.',
  not_covered: 'No countermeasure is mapped to it.',
}

/**
 * The line under a framework's name. A pack often holds only part of a
 * standard, so coverage is stated against the pack, never the standard.
 */
export function frameworkCoverageLine(framework: ComplianceMatrixFramework): string {
  if (!framework.installed || framework.packRequirementCount === null) {
    const count = framework.mappedRequirementCount
    return `Framework not installed: showing the ${count} requirement${count === 1 ? '' : 's'} countermeasures map to. Install its pack to see what is not covered.`
  }
  return `${framework.mappedRequirementCount} of the ${framework.packRequirementCount} requirements in this pack have a countermeasure. The pack may hold only part of the standard.`
}

/** Groups with the rows to show; groups left empty are dropped. */
export function visibleMatrixGroups(
  framework: ComplianceMatrixFramework,
  showNotCovered: boolean
): Array<{ name: string; rows: ComplianceMatrixRow[] }> {
  return framework.groups
    .map((group) => ({
      name: group.name,
      rows: showNotCovered ? group.rows : group.rows.filter((row) => row.state !== 'not_covered'),
    }))
    .filter((group) => group.rows.length > 0)
}

/** The count of rows in a state. */
export function stateCount(framework: ComplianceMatrixFramework, state: ComplianceMatrixState): number {
  return framework.stateCounts.find((item) => item.state === state)?.count ?? 0
}

/** The threats a row's countermeasures mitigate, each once, in number order. */
export function rowThreatNumbers(row: ComplianceMatrixRow): string[] {
  const numbers = new Set(row.controls.flatMap((control) => control.threats))
  return [...numbers].sort((left, right) => Number(left.slice(1)) - Number(right.slice(1)))
}
