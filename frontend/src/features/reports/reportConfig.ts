import type { ReportType } from '@/features/reports/types/report'

export type SectionDepth = 'full' | 'summary' | 'flagged' | 'top3' | 'count' | 'critical' | 'compliance'

export interface SectionConfig {
  id: string
  title: string
  depth: SectionDepth
}

/** The section id of the STRIDE summary; shown only for a STRIDE model (plan 11.6). */
export const STRIDE_SUMMARY_SECTION_ID = 'strideSummary'

const SECTION_MAP: Record<ReportType, SectionConfig[]> = {
  executive: [
    { id: 'executiveSummary', title: 'Executive Summary', depth: 'full' },
    { id: 'review', title: 'Review and approval', depth: 'summary' },
    { id: 'scope', title: 'Scope & Assumptions', depth: 'summary' },
    { id: 'businessObjectives', title: 'Business objectives', depth: 'summary' },
    { id: 'strideSummary', title: 'STRIDE Summary', depth: 'full' },
    { id: 'countermeasureStatus', title: 'Countermeasure Status', depth: 'full' },
    { id: 'gaps', title: 'Top Gaps', depth: 'top3' },
    { id: 'waived', title: 'Waived Countermeasures', depth: 'count' },
    { id: 'risks', title: 'Risk Register', depth: 'full' },
    { id: 'compliance', title: 'Compliance Coverage', depth: 'summary' },
    { id: 'assumptions', title: 'Assumptions Review', depth: 'flagged' },
    { id: 'findings', title: 'Key Findings', depth: 'critical' },
  ],
  technical: [
    { id: 'review', title: 'Review and approval', depth: 'summary' },
    { id: 'scope', title: 'Scope & Assumptions', depth: 'summary' },
    { id: 'businessObjectives', title: 'Business objectives', depth: 'summary' },
    { id: 'architecture', title: 'Architecture', depth: 'full' },
    { id: 'dataAssets', title: 'Data Assets', depth: 'full' },
    { id: 'components', title: 'Components & Flows', depth: 'full' },
    { id: 'strideSummary', title: 'STRIDE Summary', depth: 'full' },
    { id: 'threatDetail', title: 'Threat Detail', depth: 'full' },
    { id: 'triagedThreats', title: 'Triaged Threats', depth: 'full' },
    { id: 'countermeasureStatus', title: 'Countermeasure Status', depth: 'full' },
    { id: 'countermeasureDetail', title: 'Countermeasure Detail', depth: 'full' },
    { id: 'gaps', title: 'Gaps', depth: 'full' },
    { id: 'waived', title: 'Waived Countermeasures', depth: 'full' },
    { id: 'unattached', title: 'Unattached Controls', depth: 'full' },
    { id: 'risks', title: 'Risk Register', depth: 'summary' },
    { id: 'findings', title: 'Findings & Action Items', depth: 'full' },
  ],
  compliance: [
    { id: 'review', title: 'Review and approval', depth: 'full' },
    { id: 'scope', title: 'Scope & Assumptions', depth: 'full' },
    { id: 'businessObjectives', title: 'Business objectives', depth: 'full' },
    { id: 'dataAssets', title: 'Data Assets', depth: 'summary' },
    { id: 'strideSummary', title: 'STRIDE Summary', depth: 'summary' },
    { id: 'triagedThreats', title: 'Triaged Threats', depth: 'full' },
    { id: 'countermeasureStatus', title: 'Countermeasure Status', depth: 'full' },
    { id: 'gaps', title: 'Gaps', depth: 'full' },
    { id: 'waived', title: 'Waived Countermeasures', depth: 'full' },
    { id: 'unattached', title: 'Unattached Controls', depth: 'full' },
    { id: 'risks', title: 'Risk Register', depth: 'full' },
    { id: 'compliance', title: 'Compliance Mapping', depth: 'full' },
    { id: 'crossFrameworkMappings', title: 'Cross-Framework Mappings', depth: 'full' },
    { id: 'assumptions', title: 'Assumptions Review', depth: 'full' },
    { id: 'findings', title: 'Compliance Findings', depth: 'compliance' },
    { id: 'progressChecklist', title: 'Completion Status', depth: 'full' },
  ],
  full: [
    { id: 'executiveSummary', title: 'Executive Summary', depth: 'full' },
    { id: 'review', title: 'Review and approval', depth: 'full' },
    { id: 'scope', title: 'Scope & Assumptions', depth: 'full' },
    { id: 'businessObjectives', title: 'Business objectives', depth: 'full' },
    { id: 'architecture', title: 'Architecture', depth: 'full' },
    { id: 'dataAssets', title: 'Data Assets', depth: 'full' },
    { id: 'components', title: 'Components & Flows', depth: 'full' },
    { id: 'strideSummary', title: 'STRIDE Summary', depth: 'full' },
    { id: 'threatDetail', title: 'Threat Detail', depth: 'full' },
    { id: 'triagedThreats', title: 'Triaged Threats', depth: 'full' },
    { id: 'countermeasureStatus', title: 'Countermeasure Status', depth: 'full' },
    { id: 'countermeasureDetail', title: 'Countermeasure Detail', depth: 'full' },
    { id: 'gaps', title: 'Gaps', depth: 'full' },
    { id: 'waived', title: 'Waived Countermeasures', depth: 'full' },
    { id: 'unattached', title: 'Unattached Controls', depth: 'full' },
    { id: 'risks', title: 'Risk Register', depth: 'full' },
    { id: 'compliance', title: 'Compliance Mapping', depth: 'full' },
    { id: 'crossFrameworkMappings', title: 'Cross-Framework Mappings', depth: 'full' },
    { id: 'assumptions', title: 'Assumptions Review', depth: 'full' },
    { id: 'findings', title: 'Findings & Action Items', depth: 'full' },
    { id: 'progressChecklist', title: 'Completion Status', depth: 'full' },
  ],
}

/**
 * The STRIDE summary is a STRIDE artefact: it is shown only when the model's
 * methodologies include STRIDE (plan 11.6, STRIDE hardcoding). The comparison
 * ignores case so an imported custom name like "stride" also counts.
 */
export function isStrideSummaryVisible(methodologies: readonly string[] | null | undefined): boolean {
  if (!methodologies) return false
  return methodologies.some((methodology) => methodology.trim().toUpperCase() === 'STRIDE')
}

export interface SectionOptions {
  /** The model's methodologies (`ReportMetadata.methodologies`). */
  methodologies?: readonly string[] | null
}

/**
 * The sections of a report type. With `methodologies` given, the STRIDE
 * summary is left out for a model that does not use STRIDE.
 */
export function getSectionsForType(reportType: ReportType, options: SectionOptions = {}): SectionConfig[] {
  const sections = SECTION_MAP[reportType]
  if (options.methodologies === undefined) return sections
  if (isStrideSummaryVisible(options.methodologies)) return sections
  return sections.filter((section) => section.id !== STRIDE_SUMMARY_SECTION_ID)
}
