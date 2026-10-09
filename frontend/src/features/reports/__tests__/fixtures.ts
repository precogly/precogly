/**
 * A small report payload for the CSV, config and pentest tests: two
 * scenarios (one on several targets, one whole-system), three controls
 * including one not linked to any threat, one risk with a response.
 */

import type {
  ReportCountermeasure,
  ReportData,
  ReportRating,
  ReportThreat,
} from '@/features/reports/types/report'

export function makeRating(overrides: Partial<ReportRating> = {}): ReportRating {
  return {
    level: 'high',
    score: 16,
    methodology: 'qualitative-matrix',
    likelihoodLevel: 'high',
    likelihoodScore: 4,
    impactLevel: 'major',
    impactScore: 4,
    rationale: '',
    ...overrides,
  }
}

export function makeCountermeasure(overrides: Partial<ReportCountermeasure> = {}): ReportCountermeasure {
  return {
    id: 3,
    countermeasureName: 'Signed firmware',
    controlFunctions: ['preventive'],
    controlNature: 'technical',
    status: 'gap',
    priority: 'high',
    assignedOwnerEmail: null,
    verifiedByEmail: null,
    evidenceUrl: '',
    number: 3,
    displayNumber: 'C3',
    scope: [],
    implementedByParty: '',
    source: '',
    complianceStandards: [],
    ...overrides,
  }
}

export function makeThreat(overrides: Partial<ReportThreat> = {}): ReportThreat {
  return {
    id: 7,
    number: 7,
    displayNumber: 'T7',
    wholeSystem: false,
    targets: ['PLC', 'Control signals'],
    threatName: 'Unauthorized command injection',
    threatDescription: 'Commands injected on the control network.',
    strideCategory: 'tampering',
    businessObjectives: ['Keep line 3 running'],
    taxonomyEntries: [{ taxonomySlug: 'stride', externalId: 'tampering', title: 'Tampering' }],
    rating: makeRating(),
    status: 'exposed',
    impactDescription: '',
    threatActorText: '',
    countermeasures: [makeCountermeasure()],
    ...overrides,
  }
}

export function makeReportData(overrides: Partial<ReportData> = {}): ReportData {
  const multiTargetThreat = makeThreat()
  const wholeSystemThreat = makeThreat({
    id: 9,
    number: 9,
    displayNumber: 'T9',
    wholeSystem: true,
    targets: [],
    threatName: 'Logic tampering',
    rating: makeRating({ level: 'critical', score: 25 }),
    countermeasures: [
      makeCountermeasure({
        id: 9,
        number: 9,
        displayNumber: 'C9',
        countermeasureName: 'Change control',
        status: 'verified',
        scope: ['PLC'],
        implementedByParty: 'Plant IT',
        source: 'ISA 62443 audit',
      }),
    ],
  })

  return {
    metadata: {
      name: 'Smart Factory',
      description: '',
      criticality: 'high',
      riskScoringMethod: 'qualitative-matrix',
      methodologies: ['STRIDE', 'PASTA'],
      owningTeam: null,
      createdBy: null,
      createdAt: null,
      updatedAt: null,
      frameworks: [],
      lifecyclePhase: 'operations',
      validFrom: null,
      validUntil: null,
      reviewFrequency: 'P1Y',
      review: {
        approvalState: 'none',
        reviewer: null,
        reviewedAt: null,
        approver: null,
        approvedAt: null,
        sourceDocumentReview: null,
      },
    },
    scope: {
      description: '',
      assumptions: [
        {
          id: 1,
          blueprint: 'Main',
          description: 'The PLC rack is in a locked cabinet.',
          topic: 'security',
          validity: 'unverified',
          impact: '',
          owner: 'ops@example.com',
          validationMethod: '',
          validationDate: null,
          components: ['PLC'],
        },
      ],
      businessObjectives: [],
      outOfScopeItems: [],
      referencedModels: [],
    },
    architecture: {
      dfds: [],
      referenceImages: [],
      zones: [{ id: 1, name: 'Control Network', zoneType: 'network', trustLevel: 2, description: '' }],
      boundaries: [
        {
          id: 1,
          label: 'Plant edge',
          boundaryType: 'network',
          zoneA: 'Control Network',
          zoneB: 'Office Network',
          description: '',
          authentication: ['mtls'],
          authorization: [],
          requiresAuthentication: true,
          requiresAuthorization: false,
          dataValidation: false,
          logging: false,
          monitoring: false,
          rateLimit: '',
        },
      ],
    },
    dataAssets: [],
    components: {
      processes: [
        { id: 1, name: 'PLC', category: 'process', componentType: 'Siemens S7', actorType: '', provider: '', zone: 'Control Network', description: '' },
      ],
      dataStores: [],
      humanActors: [],
      systemActors: [],
    },
    flows: [
      {
        id: 1,
        label: 'Control signals',
        source: 'Engineering workstation',
        destination: 'PLC',
        protocol: 'S7comm',
        encrypted: false,
        flowType: 'control',
        authentication: ['none'],
        authorization: [],
        requiresAuthentication: false,
        crossesBoundary: true,
        hasSensitiveData: false,
      },
    ],
    threatAnalysis: {
      strideSummary: { tampering: 2 },
      threats: [multiTargetThreat, wholeSystemThreat],
      triagedThreats: [],
    },
    countermeasureSummary: {
      statusBreakdown: { gap: 1, verified: 1, planned: 1 },
      gaps: [
        {
          id: '3',
          countermeasureName: 'Signed firmware',
          controlNumber: 'C3',
          priority: 'high',
          assignedOwnerEmail: null,
          targets: ['PLC', 'Control signals'],
          displayNumber: 'T7',
        },
      ],
      waived: [],
      unattached: [
        {
          id: '14',
          countermeasureName: 'Backup power for PLC rack',
          controlNumber: 'C14',
          status: 'planned',
          autoGenerated: false,
          scope: ['PLC'],
        },
      ],
    },
    risks: [
      {
        id: 1,
        name: 'Line stoppage',
        description: '',
        status: 'assessed',
        statement: 'If an attacker injects commands, line 3 stops.',
        exposure: 'exposed',
        businessObjectives: ['Keep line 3 running'],
        domains: ['operational', 'safety'],
        inherent: makeRating({ level: 'critical', score: 25 }),
        residual: makeRating({ level: 'high', score: 16 }),
        target: null,
        responses: [
          {
            id: 1,
            strategy: 'reduce',
            status: 'planned',
            description: 'Sign firmware and restrict the control network.',
            priority: 'high',
            cost: '',
            ownerEmail: null,
            targetDate: null,
            countermeasures: ['C3', 'C9'],
          },
        ],
        ownerEmail: null,
        contributingThreats: [{ threatId: 7, displayNumber: 'T7', threatName: 'Unauthorized command injection', status: 'exposed', targets: ['PLC', 'Control signals'] }],
      },
    ],
    compliance: { frameworks: [] },
    summaryMetrics: {
      totalActiveThreats: 2,
      totalTriagedThreats: 0,
      threatsByStatus: { exposed: 1, mitigated: 1 },
      totalCountermeasures: 3,
      countermeasuresByStatus: { gap: 1, verified: 1, planned: 1 },
      totalGaps: 1,
      totalWaived: 0,
      totalUnattached: 1,
      totalRisks: 1,
      risksByLevel: { high: 1 },
    },
    progressChecklist: [],
    ...overrides,
  }
}
