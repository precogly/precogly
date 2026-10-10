/**
 * The Word export of the full report (plan 11.6). Sections are numbered as
 * they are built, so a section that is left out (the STRIDE summary for a
 * model that does not use STRIDE) does not leave a gap. Threats and controls
 * carry their numbers and targets; flow and boundary authentication is read
 * through the one helper (I5); canvas node types go through the canvas
 * accessors (plan 11.2).
 */

import { Document, Paragraph, Table, TextRun, HeadingLevel, ImageRun } from 'docx'
import type { ReportData, ReportRating, ReportThreat } from '../types/report'
import { isAuthenticated } from '@/lib/authentication'
import { formatTaxonomyEntryLabel } from '@/types/domain'
import { getComponentKind, getZoneType } from '@/features/dfd-editor/lib/canvas-defaults'
import { isStrideSummaryVisible } from '../reportConfig'
import { buildCountermeasureDetailRows } from './countermeasureRows'
import { deriveFindings } from './findings'
import {
  approvalStateLabel,
  assumptionTopicLabel,
  assumptionValidityLabel,
  boundaryCrossingRequirementsText,
  boundaryTypeLabel,
  componentKindLabel,
  countermeasureStatusLabel,
  defaultKindForCategory,
  flowTypeLabel,
  formatReportDate,
  lifecyclePhaseLabel,
  methodologiesText,
  methodologyNameLabel,
  responseStatusLabel,
  responseStrategyLabel,
  reviewFrequencyLabel,
  riskDomainLabel,
  riskExposureLabel,
  riskStatusLabel,
  targetsText,
  threatStatusLabel,
  zoneTrustLevelText,
  zoneTypeLabel,
} from './labels'
import {
  h1,
  h2,
  h3,
  para,
  placeholder,
  spacer,
  pageBreak,
  buildTable,
  downloadDocx,
  slugify,
  createDocumentStyles,
  createNumberingConfig,
  createPageProperties,
} from './wordHelpers'

type Block = Paragraph | Table

/** The shape of a canvas node the export reads: id, type and a data bag. */
interface CanvasNodeLike {
  id?: string
  type?: string
  data?: Record<string, unknown>
}

/** Numbers the top-level sections in build order: "3. Scope", then "3.1" for its parts. */
class SectionNumberer {
  private current = 0

  next(title: string): string {
    this.current += 1
    return `${this.current}. ${title}`
  }

  sub(index: number, title: string): string {
    return `${this.current}.${index} ${title}`
  }
}

const ACTOR_TYPE_LABELS: Record<string, string> = {
  user: 'User',
  power_user: 'Power User',
  administrator: 'Administrator',
  engineer: 'Engineer',
  third_party: 'Third Party',
  customer: 'Customer',
}

function formatActorType(actorType: string): string {
  return ACTOR_TYPE_LABELS[actorType] ?? actorType
}

function threatTargets(threat: ReportThreat): string {
  return targetsText(threat.targets, threat.wholeSystem)
}

function ratingScore(rating: ReportRating | null): string {
  return rating?.score == null ? '' : String(rating.score)
}

function ratingText(rating: ReportRating | null): string {
  if (!rating) return 'unrated'
  const score = ratingScore(rating)
  return score ? `${rating.level} (${score})` : rating.level
}

function yesNo(value: boolean): string {
  return value ? 'Yes' : 'No'
}

/** The type column of the per-diagram node inventory, through the canvas accessors. */
function canvasNodeTypeText(node: CanvasNodeLike): string {
  switch (node.type) {
    case 'trustZone':
      return zoneTypeLabel(getZoneType(node.data))
    case 'systemScope':
      return 'System'
    case 'stickyNote':
    case 'table':
      return 'Note'
    default:
      return componentKindLabel(getComponentKind(node.data, node.type))
  }
}

function canvasNodeLabel(node: CanvasNodeLike): string {
  const label = node.data?.label ?? node.data?.name
  return typeof label === 'string' && label ? label : (node.id ?? '')
}

// ---------------------------------------------------------------------------
// Section builders
// ---------------------------------------------------------------------------

function buildMetadataSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const metadata = data.metadata
  const rows = [
    ['Threat Model Name', metadata.name],
    ['Criticality', metadata.criticality],
    ['Methodologies', methodologiesText(metadata.methodologies) || 'None'],
    ['Risk Scoring Method', methodologyNameLabel(metadata.riskScoringMethod) || metadata.riskScoringMethod],
    ['Lifecycle Phase', lifecyclePhaseLabel(metadata.lifecyclePhase) || 'Not set'],
    ['Owning Team', metadata.owningTeam ?? 'None'],
    ['Created By', metadata.createdBy ?? 'Unknown'],
    ['Created', formatReportDate(metadata.createdAt) || 'Unknown'],
    ['Last Updated', formatReportDate(metadata.updatedAt) || 'Unknown'],
    ['Frameworks', metadata.frameworks.map((framework) => framework.name).join(', ') || 'None'],
  ]

  return [h1(numbers.next('Document Information')), spacer(), buildTable([3000, 6360], ['Field', 'Value'], rows), spacer()]
}

function buildReviewSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const metadata = data.metadata
  const review = metadata.review
  const personAndDate = (person: string | null, date: string | null) =>
    !person && !date ? 'Not yet' : [person, formatReportDate(date)].filter(Boolean).join(', ')
  const rows = [
    ['State', approvalStateLabel(review.approvalState) + (review.reviewDue ? ' (review due)' : '')],
    ['Reviewed by', personAndDate(review.reviewer, review.reviewedAt)],
    ['Approved by', personAndDate(review.approver, review.approvedAt)],
    ['Valid from', formatReportDate(metadata.validFrom) || 'Not set'],
    ['Valid until', formatReportDate(metadata.validUntil) || 'Not set'],
    ['Review frequency', reviewFrequencyLabel(metadata.reviewFrequency) || 'Not set'],
  ]
  const children: Block[] = [
    h1(numbers.next('Review and Approval')),
    spacer(),
    buildTable([3000, 6360], ['Field', 'Value'], rows),
    spacer(),
  ]
  const sourceReview = review.sourceDocumentReview
  if (sourceReview && Object.keys(sourceReview).length > 0) {
    children.push(
      para('Approved in the source document (history, not an approval of this model):', { italic: true }),
      buildTable(
        [3000, 6360],
        ['Field', 'Value'],
        Object.entries(sourceReview).map(([key, value]) => [key, typeof value === 'string' ? value : JSON.stringify(value)])
      ),
      spacer()
    )
  }
  return children
}

function buildSummarySection(data: ReportData, numbers: SectionNumberer): Block[] {
  const summary = data.summaryMetrics
  const statusRows = Object.entries(summary.threatsByStatus).map(([status, count]) => [threatStatusLabel(status), String(count)])
  const countermeasureRows = Object.entries(summary.countermeasuresByStatus).map(([status, count]) => [
    countermeasureStatusLabel(status),
    String(count),
  ])
  const riskRows = Object.entries(summary.risksByLevel).map(([level, count]) => [level, String(count)])

  return [
    h1(numbers.next('Executive Summary')),
    spacer(),
    h2(numbers.sub(1, 'Summary Metrics')),
    spacer(),
    buildTable(
      [4680, 4680],
      ['Metric', 'Count'],
      [
        ['Total Active Threats', String(summary.totalActiveThreats)],
        ['Total Triaged Threats', String(summary.totalTriagedThreats)],
        ['Total Countermeasures', String(summary.totalCountermeasures)],
        ['Open Gaps', String(summary.totalGaps)],
        ['Waived Countermeasures', String(summary.totalWaived)],
        ['Controls not linked to any threat', String(summary.totalUnattached)],
        ['Total Risks', String(summary.totalRisks)],
      ]
    ),
    spacer(),
    h2(numbers.sub(2, 'Threat Status Breakdown')),
    spacer(),
    buildTable([4680, 4680], ['Status', 'Count'], statusRows),
    spacer(),
    h2(numbers.sub(3, 'Countermeasure Status Breakdown')),
    spacer(),
    buildTable([4680, 4680], ['Status', 'Count'], countermeasureRows),
    spacer(),
    ...(riskRows.length > 0
      ? [h2(numbers.sub(4, 'Risk Level Breakdown')) as Block, spacer(), buildTable([4680, 4680], ['Level', 'Count'], riskRows), spacer()]
      : []),
  ]
}

function buildScopeSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const scope = data.scope
  let subsection = 1
  const children: Block[] = [
    h1(numbers.next('Scope')),
    spacer(),
    h2(numbers.sub(subsection, 'Scope Description')),
    para(scope.description || 'No scope description.'),
    spacer(),
  ]

  if (scope.businessObjectives.length > 0) {
    subsection += 1
    children.push(
      h2(numbers.sub(subsection, 'Business Objectives')),
      spacer(),
      buildTable(
        [2880, 1440, 2160, 1440, 1440],
        ['Objective', 'Criticality', 'Owner', 'Threats', 'Risks'],
        scope.businessObjectives.map((objective) => [
          objective.description ? `${objective.name}: ${objective.description}` : objective.name,
          objective.criticality,
          objective.owner,
          String(objective.threatCount),
          String(objective.riskCount),
        ])
      ),
      spacer()
    )
  }

  if (scope.assumptions.length > 0) {
    subsection += 1
    children.push(
      h2(numbers.sub(subsection, 'Assumptions')),
      spacer(),
      buildTable(
        [3600, 1440, 1440, 1440, 1440],
        ['Assumption', 'Validity', 'Topic', 'Owner', 'Validation'],
        scope.assumptions.map((assumption) => [
          assumption.description,
          assumptionValidityLabel(assumption.validity),
          assumptionTopicLabel(assumption.topic),
          assumption.owner,
          [assumption.validationMethod, formatReportDate(assumption.validationDate)].filter(Boolean).join(', '),
        ])
      ),
      spacer()
    )
  }

  if (scope.outOfScopeItems.length > 0) {
    subsection += 1
    children.push(
      h2(numbers.sub(subsection, 'Out of Scope')),
      spacer(),
      buildTable(
        [3120, 6240],
        ['Item', 'Reason'],
        scope.outOfScopeItems.map((item) => [item.name, item.reason])
      ),
      spacer()
    )
  }

  if (scope.referencedModels.length > 0) {
    subsection += 1
    children.push(
      h2(numbers.sub(subsection, 'Related Models')),
      spacer(),
      buildTable(
        [4680, 4680],
        ['Model', 'Relationship'],
        scope.referencedModels.map((model) => [model.name, model.relationType])
      ),
      spacer()
    )
  }

  return children
}

function buildArchitectureSection(data: ReportData, dfdImages: Map<string, Uint8Array>, numbers: SectionNumberer): Block[] {
  const architecture = data.architecture
  const children: Block[] = [h1(numbers.next('System Architecture')), spacer()]
  let subsection = 0

  if (architecture.dfds.length > 0) {
    subsection += 1
    children.push(
      h2(numbers.sub(subsection, 'Diagrams')),
      spacer(),
      buildTable(
        [3240, 1800, 720, 720, 2880],
        ['Diagram Name', 'Type', 'Nodes', 'Flows', 'Notes'],
        architecture.dfds.map((dfd) => [
          dfd.name,
          dfd.diagramType,
          String(dfd.nodeCount),
          String(dfd.edgeCount),
          dfd.isPrimary ? 'Primary diagram' : 'Reference diagram',
        ])
      ),
      spacer()
    )

    architecture.dfds.forEach((dfd, index) => {
      const image = dfdImages.get(dfd.id)
      children.push(
        h3(`Figure ${index + 1}: ${dfd.name}${dfd.isPrimary ? ' (Primary)' : ''}`),
        image
          ? new Paragraph({ children: [new ImageRun({ data: image, type: 'png', transformation: { width: 600, height: 360 } })] })
          : placeholder(`Diagram unavailable: ${dfd.name}`),
        spacer()
      )

      const nodes = dfd.canvasData?.nodes
      if (Array.isArray(nodes) && nodes.length > 0) {
        const nodeRows = (nodes as CanvasNodeLike[])
          .filter((node) => node && typeof node === 'object' && node.data)
          .map((node) => [canvasNodeLabel(node), canvasNodeTypeText(node)])
        if (nodeRows.length > 0) {
          children.push(
            para('Nodes in this diagram:', { italic: true }),
            buildTable([4680, 4680], ['Node Label', 'Type'], nodeRows),
            spacer()
          )
        }
      }
    })
  }

  if (architecture.zones.length > 0) {
    subsection += 1
    children.push(
      h2(numbers.sub(subsection, 'Zones')),
      spacer(),
      buildTable(
        [2400, 1800, 1200, 3960],
        ['Zone', 'Type', 'Trust Level', 'Description'],
        architecture.zones.map((zone) => [zone.name, zoneTypeLabel(zone.zoneType), zoneTrustLevelText(zone), zone.description])
      ),
      spacer()
    )
  }

  if (architecture.boundaries.length > 0) {
    subsection += 1
    children.push(
      h2(numbers.sub(subsection, 'Boundaries')),
      spacer(),
      buildTable(
        [2160, 1440, 2160, 3600],
        ['Boundary', 'Type', 'Between', 'Crossing Requirements'],
        architecture.boundaries.map((boundary) => [
          boundary.label,
          boundaryTypeLabel(boundary.boundaryType),
          `${boundary.zoneA} and ${boundary.zoneB}`,
          boundaryCrossingRequirementsText(boundary),
        ])
      ),
      spacer()
    )
  }

  if (architecture.referenceImages.length > 0) {
    subsection += 1
    children.push(
      h2(numbers.sub(subsection, 'Reference Images')),
      spacer(),
      buildTable(
        [4680, 4680],
        ['Filename', 'Description'],
        architecture.referenceImages.map((image) => [image.filename, image.description])
      ),
      spacer()
    )
  }

  return children
}

function buildDataAssetsSection(data: ReportData, numbers: SectionNumberer): Block[] {
  return [
    h1(numbers.next('Data Assets')),
    spacer(),
    data.dataAssets.length > 0
      ? buildTable(
          [1800, 1440, 1260, 1260, 1260, 2340],
          ['Name', 'Classification', 'Confidentiality', 'Integrity', 'Availability', 'Description'],
          data.dataAssets.map((asset) => [
            asset.name,
            asset.classification,
            asset.confidentiality,
            asset.integrity,
            asset.availability,
            asset.description,
          ])
        )
      : para('No data assets defined.'),
    spacer(),
  ]
}

function buildComponentsSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const components = data.components
  const allComponents = [
    ...components.processes.map((component) => ({ ...component, categoryLabel: 'Process' })),
    ...components.dataStores.map((component) => ({ ...component, categoryLabel: 'Data Store' })),
    ...components.humanActors.map((component) => ({ ...component, categoryLabel: 'Human Actor' })),
    ...components.systemActors.map((component) => ({ ...component, categoryLabel: 'System Actor' })),
  ]

  if (allComponents.length === 0 && data.flows.length === 0) return []

  const children: Block[] = [h1(numbers.next('Component Inventory')), spacer()]

  if (allComponents.length > 0) {
    children.push(
      buildTable(
        [2160, 1440, 1440, 1440, 1440, 1440],
        ['Name', 'Category', 'Kind', 'Technology', 'Zone', 'Description'],
        allComponents.map((component) => {
          const categoryText =
            component.categoryLabel === 'Human Actor' && component.actorType
              ? `${component.categoryLabel}\n(${formatActorType(component.actorType)})`
              : component.categoryLabel
          return [
            component.name,
            categoryText,
            componentKindLabel(component.kind ?? defaultKindForCategory(component.category)),
            component.componentType,
            component.zone ?? 'No zone',
            component.description,
          ]
        })
      ),
      spacer()
    )
  }

  if (data.flows.length > 0) {
    children.push(
      h2(numbers.sub(1, 'Flows')),
      spacer(),
      buildTable(
        [1620, 1080, 1260, 1260, 1080, 900, 1260, 900],
        ['Label', 'Type', 'Source', 'Destination', 'Protocol', 'Encrypted', 'Authenticated', 'Crosses Boundary'],
        data.flows.map((flow) => [
          flow.label,
          flowTypeLabel(flow.flowType),
          flow.source ?? '',
          flow.destination ?? '',
          flow.protocol || '',
          yesNo(flow.encrypted),
          isAuthenticated(flow.authentication) ? `Yes (${flow.authentication.join(', ')})` : 'No',
          yesNo(flow.crossesBoundary),
        ])
      ),
      spacer()
    )
  }

  return children
}

function buildStrideSummarySection(data: ReportData, numbers: SectionNumberer): Block[] {
  return [
    h1(numbers.next('STRIDE Summary')),
    spacer(),
    buildTable(
      [6240, 3120],
      ['STRIDE Category', 'Threats'],
      Object.entries(data.threatAnalysis.strideSummary).map(([category, count]) => [category, String(count)])
    ),
    spacer(),
  ]
}

function buildThreatAnalysisSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const threats = data.threatAnalysis.threats

  return [
    h1(numbers.next('Threat Analysis')),
    spacer(),
    ...(threats.length > 0
      ? [
          para(`This section documents ${threats.length} active threats. Each is numbered so it can be cited.`),
          spacer(),
          buildTable(
            [720, 2160, 1800, 1440, 1080, 960, 1200],
            ['#', 'Threat', 'Targets', 'Classifications', 'Rating', 'Status', 'Controls'],
            threats.map((threat) => [
              threat.displayNumber,
              threat.threatName,
              threatTargets(threat),
              (threat.taxonomyEntries ?? []).map((entry) => formatTaxonomyEntryLabel(entry)).join(', '),
              ratingText(threat.rating),
              threatStatusLabel(threat.status),
              threat.countermeasures.map((countermeasure) => countermeasure.displayNumber).join(', '),
            ])
          ) as Block,
        ]
      : [para('No active threats defined.') as Block]),
    spacer(),
  ]
}

function buildTriagedThreatsSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const triaged = data.threatAnalysis.triagedThreats
  return [
    h1(numbers.next('Triaged Threats')),
    spacer(),
    triaged.length > 0
      ? buildTable(
          [720, 2400, 2160, 1440, 2640],
          ['#', 'Threat', 'Targets', 'Decision', 'Rationale'],
          triaged.map((threat) => [
            threat.displayNumber,
            threat.threatName,
            targetsText(threat.targets),
            threat.triageStatus,
            threat.decisionRationale,
          ])
        )
      : para('No triaged threats.'),
    spacer(),
  ]
}

function buildCountermeasureStatusSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const rows = Object.entries(data.countermeasureSummary.statusBreakdown).map(([status, count]) => [
    countermeasureStatusLabel(status),
    String(count),
  ])
  const unattachedCount = data.countermeasureSummary.unattached.length
  return [
    h1(numbers.next('Countermeasure Status')),
    spacer(),
    buildTable([6240, 3120], ['Status', 'Count'], rows),
    ...(unattachedCount > 0
      ? [para(`${unattachedCount} of these controls are not linked to any threat and are left out of gap and coverage figures.`, { italic: true }) as Block]
      : []),
    spacer(),
  ]
}

function buildCountermeasuresSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const rows = buildCountermeasureDetailRows(data.threatAnalysis.threats)

  return [
    h1(numbers.next('Countermeasure Detail')),
    spacer(),
    rows.length > 0
      ? buildTable(
          [600, 1800, 960, 960, 1440, 1200, 1200, 1200],
          ['#', 'Countermeasure', 'Status', 'Threats', 'Applies To', 'Implemented By', 'Source', 'Compliance'],
          rows.map((row) => [
            row.displayNumber,
            row.countermeasureName,
            countermeasureStatusLabel(row.status),
            row.threatNumbers.join(', '),
            targetsText(row.scope),
            row.implementedByParty,
            row.source,
            row.complianceStandards.join(', '),
          ])
        )
      : para('No countermeasures linked to a threat.'),
    spacer(),
  ]
}

function buildGapsSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const gaps = data.countermeasureSummary.gaps
  return [
    h1(numbers.next('Gaps')),
    spacer(),
    gaps.length > 0
      ? buildTable(
          [720, 2520, 960, 2160, 1200, 1800],
          ['#', 'Countermeasure', 'Threat', 'Targets', 'Priority', 'Assigned Owner'],
          gaps.map((gap) => [
            gap.controlNumber,
            gap.countermeasureName,
            gap.displayNumber ?? '',
            targetsText(gap.targets),
            gap.priority,
            gap.assignedOwnerEmail ?? 'Unassigned',
          ])
        )
      : para('No open gaps.'),
    spacer(),
  ]
}

function buildWaivedSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const waived = data.countermeasureSummary.waived
  return [
    h1(numbers.next('Waived Countermeasures')),
    spacer(),
    waived.length > 0
      ? buildTable(
          [720, 3600, 1200, 3840],
          ['#', 'Countermeasure', 'Threat', 'Targets'],
          waived.map((item) => [item.controlNumber, item.countermeasureName, item.displayNumber ?? '', targetsText(item.targets)])
        )
      : para('No waived countermeasures.'),
    spacer(),
  ]
}

function buildUnattachedSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const unattached = data.countermeasureSummary.unattached
  return [
    h1(numbers.next('Controls Not Linked to Any Threat')),
    spacer(),
    para('Not counted in coverage or gap figures.', { italic: true }),
    unattached.length > 0
      ? buildTable(
          [720, 3600, 1920, 3120],
          ['#', 'Countermeasure', 'Status', 'Applies To'],
          unattached.map((item) => [
            item.controlNumber,
            item.countermeasureName,
            countermeasureStatusLabel(item.status),
            targetsText(item.scope),
          ])
        )
      : para('Every control is linked to a threat.'),
    spacer(),
  ]
}

function buildRisksSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const children: Block[] = [h1(numbers.next('Risk Register')), spacer()]

  if (data.risks.length === 0) {
    children.push(para('No risks defined.'), spacer())
    return children
  }

  children.push(
    buildTable(
      [1800, 1080, 1080, 1080, 1080, 1080, 1080, 1080],
      ['Risk', 'Status', 'Exposure', 'Domains', 'Inherent', 'Residual', 'Target', 'Owner'],
      data.risks.map((risk) => [
        risk.name,
        riskStatusLabel(risk.status),
        riskExposureLabel(risk.exposure),
        risk.domains.map(riskDomainLabel).join(', '),
        ratingText(risk.inherent),
        ratingText(risk.residual),
        ratingText(risk.target),
        risk.ownerEmail ?? 'Unassigned',
      ])
    ),
    spacer()
  )

  data.risks.forEach((risk, index) => {
    children.push(h3(numbers.sub(index + 1, risk.name)))
    if (risk.statement) children.push(para(`Statement: ${risk.statement}`))
    if (risk.description) children.push(para(risk.description))
    if (risk.contributingThreats.length > 0) {
      children.push(
        para(
          `Contributing threats: ${risk.contributingThreats
            .map((threat) => `${threat.displayNumber} ${threat.threatName} (${threatStatusLabel(threat.status)})`)
            .join('; ')}`
        )
      )
    }
    if (risk.businessObjectives.length > 0) children.push(para(`Business objectives: ${risk.businessObjectives.join(', ')}`))
    if (risk.responses.length > 0) {
      children.push(
        spacer(),
        buildTable(
          [1200, 2880, 1200, 1440, 1200, 1440],
          ['Strategy', 'Description', 'Status', 'Owner', 'Target Date', 'Controls'],
          risk.responses.map((response) => [
            responseStrategyLabel(response.strategy),
            response.description,
            responseStatusLabel(response.status),
            response.ownerEmail ?? '',
            formatReportDate(response.targetDate),
            response.countermeasures.join(', '),
          ])
        )
      )
    }
    children.push(spacer())
  })

  return children
}

function buildComplianceSection(data: ReportData, numbers: SectionNumberer): Block[] {
  return [
    h1(numbers.next('Compliance Mapping')),
    spacer(),
    data.compliance.frameworks.length > 0
      ? buildTable(
          [3240, 1680, 1680, 2760],
          ['Framework', 'Total Requirements', 'Covered', 'Coverage %'],
          data.compliance.frameworks.map((framework) => [
            framework.name,
            String(framework.totalRequirements),
            String(framework.coveredRequirements),
            `${framework.coveragePercentage.toFixed(1)}%`,
          ])
        )
      : para('No compliance frameworks linked.'),
    spacer(),
  ]
}

function buildCrossFrameworkMappingsSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const groups = data.compliance.crossFrameworkMappings ?? []
  const children: Block[] = [h1(numbers.next('Cross-Framework Mappings')), spacer()]

  if (groups.length === 0) {
    children.push(para('No cross-framework requirement mappings available.'), spacer())
    return children
  }

  for (const group of groups) {
    children.push(
      h2(`${group.sourceFramework} to ${group.targetFramework}`),
      spacer(),
      buildTable(
        [1800, 3000, 1800, 2760],
        ['Source', 'Source Description', 'Target', 'Target Description / Sufficiency'],
        group.mappings.map((entry) => [
          entry.fromSectionCode,
          entry.fromDescription,
          entry.toSectionCode,
          `${entry.toDescription}\n${entry.sufficiency}`,
        ])
      ),
      spacer()
    )
  }

  return children
}

function buildAssumptionsReviewSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const assumptions = data.scope.assumptions
  return [
    h1(numbers.next('Assumptions Review')),
    spacer(),
    assumptions.length > 0
      ? buildTable(
          [1200, 3240, 1200, 1440, 1440, 840],
          ['Validity', 'Assumption', 'Topic', 'Owner', 'Validation', 'Components'],
          assumptions.map((assumption) => [
            assumptionValidityLabel(assumption.validity),
            assumption.impact ? `${assumption.description}\nImpact if invalid: ${assumption.impact}` : assumption.description,
            assumptionTopicLabel(assumption.topic),
            assumption.owner,
            [assumption.validationMethod, formatReportDate(assumption.validationDate)].filter(Boolean).join(', '),
            assumption.components.join(', '),
          ])
        )
      : para('No assumptions defined.'),
    spacer(),
  ]
}

function buildFindingsSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const findings = deriveFindings(data, 'full').map((finding) => [
    finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1),
    finding.title,
    finding.detail,
  ])
  if (findings.length === 0) {
    findings.push(['Info', 'No significant findings', 'No critical or high-priority findings were derived from the report data.'])
  }

  return [h1(numbers.next('Findings & Action Items')), spacer(), buildTable([1080, 3240, 5040], ['Severity', 'Finding', 'Detail'], findings), spacer()]
}

function buildProgressSection(data: ReportData, numbers: SectionNumberer): Block[] {
  const checklistRows = data.progressChecklist.map((item) => [
    item.checked ? 'Complete' : 'Incomplete',
    item.label,
    item.autoComputed ? 'Automatic' : 'Manual',
  ])
  const children: Block[] = [h1(numbers.next('Completion Status')), spacer()]

  if (checklistRows.length > 0) {
    children.push(buildTable([1440, 5760, 2160], ['Status', 'Checklist Item', 'Source'], checklistRows), spacer())
  }

  if (data.completionStatus) {
    children.push(h2(numbers.sub(1, 'Completion Cross-Check')), spacer())
    for (const item of data.completionStatus.systemDefinition) {
      children.push(para(`${item.checked ? 'Complete' : 'Incomplete'}: ${item.label} (${item.countLabel})`))
    }
    for (const item of data.completionStatus.coverage) {
      children.push(para(`${item.label}: ${item.numerator}/${item.denominator} (${item.percentage}%)`))
    }
    children.push(spacer())
  }

  if (checklistRows.length === 0 && !data.completionStatus) children.push(para('No completion data available.'), spacer())
  return children
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function exportWordDoc(data: ReportData, modelName: string, dfdImages: Map<string, Uint8Array>): Promise<void> {
  const numbers = new SectionNumberer()
  const sectionBuilders: Array<(numbers: SectionNumberer) => Block[]> = [
    (n) => buildMetadataSection(data, n),
    (n) => buildReviewSection(data, n),
    (n) => buildSummarySection(data, n),
    (n) => buildScopeSection(data, n),
    (n) => buildArchitectureSection(data, dfdImages, n),
    (n) => buildDataAssetsSection(data, n),
    (n) => buildComponentsSection(data, n),
    ...(isStrideSummaryVisible(data.metadata.methodologies) ? [(n: SectionNumberer) => buildStrideSummarySection(data, n)] : []),
    (n) => buildThreatAnalysisSection(data, n),
    (n) => buildTriagedThreatsSection(data, n),
    (n) => buildCountermeasureStatusSection(data, n),
    (n) => buildCountermeasuresSection(data, n),
    (n) => buildGapsSection(data, n),
    (n) => buildWaivedSection(data, n),
    (n) => buildUnattachedSection(data, n),
    (n) => buildRisksSection(data, n),
    (n) => buildComplianceSection(data, n),
    (n) => buildCrossFrameworkMappingsSection(data, n),
    (n) => buildAssumptionsReviewSection(data, n),
    (n) => buildFindingsSection(data, n),
    (n) => buildProgressSection(data, n),
  ]

  const children: Block[] = [
    new Paragraph({ heading: HeadingLevel.TITLE, children: [new TextRun({ text: modelName })] }),
    new Paragraph({
      children: [new TextRun({ text: 'Threat Model: Full Report', size: 28, color: '444444' })],
    }),
    new Paragraph({
      children: [
        new TextRun({
          text: `Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`,
          size: 24,
          color: '888888',
        }),
      ],
    }),
    spacer(),
    placeholder('This document is auto-generated. Review all sections before submission.'),
  ]

  for (const build of sectionBuilders) {
    const blocks = build(numbers)
    if (blocks.length === 0) continue
    children.push(pageBreak(), ...blocks)
  }

  const doc = new Document({
    styles: createDocumentStyles(),
    numbering: createNumberingConfig(),
    sections: [{ properties: createPageProperties(), children }],
  })

  await downloadDocx(doc, `${slugify(modelName)}-threat-model-report.docx`)
}
