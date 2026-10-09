import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  buildGuestDocument,
  deserializeCycloneDxToGuest,
  newDocumentState,
  type GuestExportInput,
} from '../lib/cyclonedx-guest'
import { removeDiagramElements, removeThreats, deriveThreatStatus } from '../lib/guest-model'
import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'
import type { GuestThreat, GuestCountermeasure, GuestSystemContext, GuestDocumentState } from '../types'
import type { CycloneDxDocument } from '../lib/cyclonedx-types'
import { BACKEND_AVAILABLE, assertValidTmBom, readReferenceFixture } from './tmbom-schema'
import { canonical, canonicalLines } from './tmbom-canonical'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeNode(id: string, type: string, label: string, overrides: Record<string, unknown> = {}, parentId?: string): DiagramNode {
  return {
    id,
    type,
    position: { x: 0, y: 0 },
    ...(parentId ? { parentId } : {}),
    data: { label, ...overrides },
  } as DiagramNode
}

function makeEdge(id: string, source: string, target: string, label = '', overrides: Record<string, unknown> = {}): DiagramEdge {
  return {
    id,
    type: 'dataFlow',
    source,
    target,
    data: { label, encrypted: false, authentication: [], ...overrides },
  } as DiagramEdge
}

function makeBoundary(id: string, source: string, target: string, overrides: Record<string, unknown> = {}): DiagramEdge {
  return { id, type: 'trustBoundary', source, target, data: { label: 'Edge', ...overrides } } as DiagramEdge
}

let nextThreatNumber = 1
let nextCountermeasureNumber = 1

function makeThreat(overrides: Partial<GuestThreat> & { name: string }): GuestThreat {
  const number = overrides.number ?? nextThreatNumber++
  return {
    id: `threat-${overrides.name.toLowerCase().replace(/\s+/g, '-')}`,
    description: '',
    level: 'medium',
    status: 'open',
    targets: [],
    wholeSystem: false,
    hiddenTargetRefs: [],
    hiddenBlueprintTargetCount: 0,
    createdAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
    number,
  }
}

function makeCountermeasure(overrides: Partial<GuestCountermeasure> & { name: string; threatIds: string[] }): GuestCountermeasure {
  const number = overrides.number ?? nextCountermeasureNumber++
  return {
    id: `cm-${overrides.name.toLowerCase().replace(/\s+/g, '-')}`,
    description: '',
    controlFunction: ['preventive'],
    controlNature: 'technical',
    targets: [],
    hiddenTargetRefs: [],
    createdAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
    number,
  }
}

function emptyContext(): GuestSystemContext {
  return {
    session: { facilitator: '', participants: [], meetingDate: '' },
    systemInfo: { description: '', criticality: 'medium' },
    dataAssets: [],
    assumptions: [],
    outOfScopeItems: [],
  }
}

function stateWithCounters(): GuestDocumentState {
  const state = newDocumentState()
  state.nextThreatNumber = nextThreatNumber
  state.nextCountermeasureNumber = nextCountermeasureNumber
  return state
}

function exportInput(overrides: Partial<GuestExportInput> = {}): GuestExportInput {
  return {
    title: 'Test Diagram',
    nodes: [],
    edges: [],
    threats: [],
    countermeasures: [],
    systemContext: emptyContext(),
    documentState: stateWithCounters(),
    ...overrides,
  }
}

function exportDocument(overrides: Partial<GuestExportInput> = {}) {
  const result = buildGuestDocument(exportInput(overrides))
  assertValidTmBom(result.document, 'export')
  return result
}

function roundTrip(overrides: Partial<GuestExportInput> = {}) {
  const result = exportDocument(overrides)
  return { result, loaded: deserializeCycloneDxToGuest(result.json) }
}

/** A guest model that touches every slice the guest editor models. */
function sampleModel(): Partial<GuestExportInput> {
  const nodes = [
    makeNode('zone-internet', 'trustZone', 'Internet', { zoneType: 'trust', trustLevel: 10, zoneColor: '#ef4444' }),
    makeNode('zone-core', 'trustZone', 'Core', { zoneType: 'network', trustLevel: 80 }),
    makeNode('user', 'humanActor', 'Customer', { actorType: 'customer' }, 'zone-internet'),
    makeNode('api', 'process', 'API', { description: 'Public API', dataSensitivity: 'confidential', kind: 'service' }, 'zone-core'),
    makeNode('db', 'datastore', 'Database', { dataStoreType: 'sql', technology: 'PostgreSQL' }, 'zone-core'),
    makeNode('partner', 'systemActor', 'Payment gateway', { systemType: 'api' }),
    makeNode('note', 'stickyNote', 'Remember the audit', { noteColor: 'yellow' }),
  ]
  const edges = [
    makeEdge('flow-login', 'user', 'api', 'Login', { flowType: 'data', protocol: 'HTTPS', port: 443, encrypted: true, authentication: ['oauth2'], dataClassification: ['pii'], hasSensitiveData: true }),
    makeEdge('flow-query', 'api', 'db', 'Query', { flowType: 'data', authentication: [] }),
    makeEdge('flow-signal', 'partner', 'api', '', { flowType: 'signal' }),
    makeBoundary('boundary-edge', 'zone-internet', 'zone-core', {
      boundaryType: 'trust',
      authenticationMethods: ['oauth2', 'Badge'],
      accessControlMethods: ['rbac'],
      dataValidation: true,
      rateLimit: '100 rps',
      accessTokenExpires: true,
      accessTokenTtl: 900,
      canUserLogout: true,
    }),
  ]
  const threats = [
    makeThreat({ name: 'SQL injection', description: 'Injected SQL', level: 'high', category: 'tampering', status: 'mitigate', targets: [{ id: 'api', type: 'component' }, { id: 'flow-query', type: 'flow' }] }),
    makeThreat({ name: 'Backup theft', level: 'critical', status: 'accept', decisionRationale: 'Accepted for now', wholeSystem: true }),
    makeThreat({ name: 'Boundary crossing', level: 'info', targets: [{ id: 'boundary-edge', type: 'boundary' }, { id: 'zone-core', type: 'zone' }] }),
  ]
  const countermeasures = [
    makeCountermeasure({ name: 'Parameterised queries', description: 'Bind parameters', threatIds: [threats[0].id, threats[2].id], controlFunction: ['preventive', 'detective'], targets: [{ id: 'api', type: 'component' }] }),
    makeCountermeasure({ name: 'Security training', threatIds: [threats[2].id], controlFunction: ['deterrent'], controlNature: 'administrative' }),
  ]
  const systemContext: GuestSystemContext = {
    session: { facilitator: 'Alice', participants: ['Bob'], meetingDate: '2026-01-15' },
    systemInfo: { description: 'E-commerce platform', criticality: 'high' },
    dataAssets: [
      { id: 'da-1', name: 'Card records', description: 'Card data', classification: 'confidential', confidentiality: 'high', integrity: 'medium', availability: 'low', complianceTags: ['PCI DSS'], dataSensitivity: ['pci', 'pii'] },
    ],
    assumptions: [{ id: 'a-1', description: 'TLS everywhere', validity: 'verified', topic: 'security' }],
    outOfScopeItems: [
      { id: 'oos-1', name: 'Mainframe', reason: 'Separate model' },
      { id: 'oos-2', name: 'Payment gateway', reason: '' },
    ],
  }
  return { nodes, edges, threats, countermeasures, systemContext, notationStyle: 'dfd3' }
}

// The schema check needs the backend tree: see BACKEND_AVAILABLE.
const describeWithBackend = describe.skipIf(!BACKEND_AVAILABLE)

beforeEach(() => {
  nextThreatNumber = 1
  nextCountermeasureNumber = 1
  vi.spyOn(console, 'warn')
})

afterEach(() => {
  expect(console.warn).not.toHaveBeenCalled()
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// 1. Every export validates
// ---------------------------------------------------------------------------

describeWithBackend('export shape', () => {
  it('validates an empty document and the sample model against the pinned schema', () => {
    exportDocument()
    const { document } = exportDocument(sampleModel())
    expect(document.specFormat).toBe('CycloneDX')
    expect(document.specVersion).toBe('2.0')
    expect(document.blueprints).toHaveLength(1)
  })

  it('writes the slices the backend writes', () => {
    const { document } = exportDocument(sampleModel())
    const blueprint = document.blueprints![0]
    expect(blueprint.zones?.map((zone) => [zone.name, zone.type])).toEqual([['Internet', 'trust'], ['Core', 'network']])
    expect(blueprint.zones?.[1].properties).toEqual([{ name: 'precogly:trust-level', value: '80' }])
    const api = blueprint.assets!.find((asset) => asset.name === 'API')!
    expect(api.type).toBe('service')
    expect(api.zone).toBe('zone-zone-core')
    expect(api.properties).toEqual([
      { name: 'precogly:category', value: 'process' },
      { name: 'precogly:data-sensitivity', value: 'confidential' },
    ])
    const customer = blueprint.assets!.find((asset) => asset.name === 'Customer')!
    expect(customer.type).toBe('actor')
    expect(customer.properties).toEqual([
      { name: 'precogly:category', value: 'external_human_actor' },
      { name: 'precogly:actor-type', value: 'customer' },
    ])
    expect(blueprint.dataStores?.[0]).toMatchObject({ name: 'Database', type: 'relational', zone: 'zone-zone-core' })
    expect(blueprint.dataStores?.[0].properties).toEqual([{ name: 'precogly:data-store-type', value: 'sql' }])
    // Sticky notes stay in the canvas only
    expect(blueprint.assets?.some((asset) => asset.name === 'Remember the audit')).toBe(false)

    const login = blueprint.flows!.find((flow) => flow.name === 'Login')!
    expect(login).toMatchObject({ type: 'data', source: 'asset-user', destination: 'asset-api', encrypted: true, protocols: ['HTTPS'], authentication: ['oauth2'] })
    expect(login.properties).toEqual([
      { name: 'precogly:port', value: '443' },
      { name: 'precogly:has-sensitive-data', value: 'true' },
      { name: 'precogly:data-classification', value: '["pii"]' },
    ])
    const signal = blueprint.flows!.find((flow) => flow.type === 'signal')!
    expect(signal.name).toBe('Payment gateway to API')
    expect(signal.encrypted).toBeUndefined()

    const boundary = blueprint.boundaries![0]
    expect(boundary).toMatchObject({ zones: ['zone-zone-internet', 'zone-zone-core'], type: 'trust', name: 'Edge' })
    expect(boundary.crossingRequirements).toEqual({
      authentication: ['oauth2', { name: 'Badge' }],
      authorization: ['rbac'],
      dataValidation: true,
      rateLimit: '100 rps',
    })
    expect(boundary.sessionManagement).toEqual({ accessTokenExpires: true, accessTokenTtl: 900, userLogout: true })

    const dataSet = blueprint.dataSets![0]
    expect(dataSet).toMatchObject({ name: 'Card records', description: 'Card data' })
    expect(dataSet.dataProfiles).toEqual([{ 'bom-ref': 'dataset-da-1-profile', name: 'Card records profile', classification: 'confidential', regulations: ['PCI DSS'] }])
    expect(dataSet.properties).toEqual([
      { name: 'precogly:confidentiality', value: 'high' },
      { name: 'precogly:availability', value: 'low' },
      { name: 'precogly:data-sensitivity-tags', value: '["pci","pii"]' },
    ])
    expect(blueprint.assumptions).toEqual([{ 'bom-ref': 'assumption-a-1', description: 'TLS everywhere', validity: 'verified', topic: 'security' }])
    expect(blueprint.scope).toEqual({
      name: 'Test Diagram scope',
      excludedComponents: ['asset-partner'],
      properties: [{ name: 'precogly:out-of-scope', value: '{"name":"Mainframe","reason":"Separate model"}' }],
    })
    const visualization = blueprint.visualizations![0]
    expect(visualization.type).toEqual({ type: 'data-flow' })
    expect(visualization.attachment?.mediaType).toBe('application/vnd.precogly.dfd+json')
    expect(visualization.properties).toEqual([
      { name: 'precogly:diagram-type', value: 'level1' },
      { name: 'precogly:primary', value: 'true' },
    ])
    const canvas = JSON.parse(Buffer.from(visualization.attachment!.content, 'base64').toString('utf8'))
    expect(canvas.notation_style).toBe('dfd3')
    expect(canvas.nodes.find((node: { id: string }) => node.id === 'api').data).toEqual({
      label: 'API', description: 'Public API', data_sensitivity: 'confidential', kind: 'service', bom_ref: 'asset-api',
    })
    expect(canvas.edges.find((edge: { id: string }) => edge.id === 'boundary-edge').data.bom_ref).toBe('boundary-boundary-edge')

    const threats = document.threats!
    expect(threats.threats?.map((threat) => threat['bom-ref'])).toEqual(['threat-custom-threat-sql-injection', 'threat-custom-threat-backup-theft', 'threat-custom-threat-boundary-crossing'])
    expect(threats.threats?.[0]).toMatchObject({ name: 'SQL injection', description: 'Injected SQL', categories: [{ taxonomy: 'STRIDE', category: 'tampering' }], mitigations: ['control-cm-parameterised-queries'] })
    const scenario = threats.scenarios![0]
    expect(scenario).toMatchObject({
      'bom-ref': 'scenario-threat-sql-injection',
      name: 'SQL injection',
      threats: ['threat-custom-threat-sql-injection'],
      affectedAssets: ['asset-api', 'flow-flow-query'],
      riskScore: { level: 'high', methodology: { name: 'manual' } },
    })
    expect(scenario.properties).toEqual([
      { name: 'precogly:number', value: '1' },
      { name: 'precogly:threat-status', value: 'addressable' },
      { name: 'precogly:triage-status', value: 'mitigate' },
    ])
    expect(threats.scenarios![1].affectedAssets).toEqual(['system-model-1'])
    expect(threats.scenarios![1].properties).toContainEqual({ name: 'precogly:decision-rationale', value: 'Accepted for now' })
    expect(threats.scenarios![2].affectedAssets).toEqual(['boundary-boundary-edge', 'zone-zone-core'])
    expect(threats.scenarios![2].riskScore).toEqual({ level: 'info', methodology: { name: 'manual' } })
    expect(threats.trustBoundaries).toEqual([
      {
        'bom-ref': 'trustboundary-boundary-edge',
        boundary: 'boundary-boundary-edge',
        name: 'Edge',
        trustLevel: 'untrusted',
        threatsAtBoundary: ['scenario-threat-boundary-crossing'],
      },
    ])

    const control = document.controls![0]
    expect(control).toMatchObject({ name: 'Parameterised queries', category: 'preventive', status: 'recommended', appliesTo: ['asset-api'] })
    expect(control.properties).toEqual([
      { name: 'precogly:number', value: '1' },
      { name: 'precogly:control-functions', value: '["preventive","detective"]' },
      { name: 'precogly:control-nature', value: 'technical' },
      { name: 'precogly:mitigates', value: '["scenario-threat-sql-injection","scenario-threat-boundary-crossing"]' },
    ])
    expect(document.controls![1].appliesTo).toBeUndefined()

    expect(document.metadata?.component).toEqual({
      type: 'application',
      'bom-ref': 'system-model-1',
      name: 'Test Diagram',
      properties: [{ name: 'precogly:criticality', value: 'high' }],
    })
    expect(document.properties).toEqual([
      { name: 'precogly:next-threat-number', value: '4' },
      { name: 'precogly:next-countermeasure-number', value: '3' },
      { name: 'precogly-guest:session', value: '{"facilitator":"Alice","meetingDate":"2026-01-15","participants":["Bob"]}' },
    ])
  })
})

// ---------------------------------------------------------------------------
// 2. Round trip of a guest-built model
// ---------------------------------------------------------------------------

describeWithBackend('guest round trip', () => {
  it('reads back nodes, edges, threats, countermeasures and the context', () => {
    const { loaded } = roundTrip(sampleModel())
    expect(loaded.warnings).toEqual([])
    expect(loaded.title).toBe('Test Diagram')
    expect(loaded.notationStyle).toBe('dfd3')
    expect(loaded.nodes.map((node) => node.id)).toEqual(['zone-internet', 'zone-core', 'user', 'api', 'db', 'partner', 'note'])
    expect(loaded.nodes.find((node) => node.id === 'api')?.parentId).toBe('zone-core')
    expect(loaded.nodes.find((node) => node.id === 'zone-core')?.data).toMatchObject({ zoneType: 'network', trustLevel: 80, bomRef: 'zone-zone-core' })
    expect(loaded.nodes.find((node) => node.id === 'db')?.data).toMatchObject({ dataStoreType: 'sql', technology: 'PostgreSQL' })
    const login = loaded.edges.find((edge) => edge.id === 'flow-login')!
    expect(login.data).toMatchObject({ label: 'Login', flowType: 'data', protocol: 'HTTPS', port: 443, encrypted: true, authentication: ['oauth2'], dataClassification: ['pii'], hasSensitiveData: true })
    expect(loaded.edges.find((edge) => edge.id === 'flow-signal')?.data?.label).toBe('')
    const boundary = loaded.edges.find((edge) => edge.id === 'boundary-edge')!
    expect(boundary.data).toMatchObject({
      boundaryType: 'trust', authenticationMethods: ['oauth2', 'Badge'], accessControlMethods: ['rbac'], dataValidation: true, rateLimit: '100 rps', accessTokenExpires: true, accessTokenTtl: 900, canUserLogout: true,
    })

    expect(loaded.threats.map((threat) => [threat.number, threat.name, threat.level, threat.status])).toEqual([
      [1, 'SQL injection', 'high', 'mitigate'],
      [2, 'Backup theft', 'critical', 'accept'],
      [3, 'Boundary crossing', 'info', 'open'],
    ])
    expect(loaded.threats[0].targets).toEqual([{ id: 'api', type: 'component' }, { id: 'flow-query', type: 'flow' }])
    expect(loaded.threats[0].category).toBe('tampering')
    expect(loaded.threats[1]).toMatchObject({ wholeSystem: true, targets: [], decisionRationale: 'Accepted for now' })
    expect(loaded.threats[2].targets).toEqual([{ id: 'boundary-edge', type: 'boundary' }, { id: 'zone-core', type: 'zone' }])

    expect(loaded.countermeasures.map((countermeasure) => [countermeasure.number, countermeasure.name])).toEqual([[1, 'Parameterised queries'], [2, 'Security training']])
    expect(loaded.countermeasures[0].threatIds).toEqual([loaded.threats[0].id, loaded.threats[2].id])
    expect(loaded.countermeasures[0].controlFunction).toEqual(['preventive', 'detective'])
    expect(loaded.countermeasures[0].targets).toEqual([{ id: 'api', type: 'component' }])
    expect(loaded.countermeasures[1]).toMatchObject({ controlNature: 'administrative', targets: [] })

    expect(loaded.systemContext.session).toEqual({ facilitator: 'Alice', participants: ['Bob'], meetingDate: '2026-01-15' })
    expect(loaded.systemContext.systemInfo).toEqual({ description: 'E-commerce platform', criticality: 'high' })
    expect(loaded.systemContext.dataAssets[0]).toMatchObject({ name: 'Card records', description: 'Card data', classification: 'confidential', confidentiality: 'high', integrity: 'medium', availability: 'low', complianceTags: ['PCI DSS'], dataSensitivity: ['pci', 'pii'] })
    expect(loaded.systemContext.assumptions[0]).toMatchObject({ description: 'TLS everywhere', validity: 'verified', topic: 'security' })
    expect(loaded.systemContext.outOfScopeItems.map((item) => item.name).sort()).toEqual(['Mainframe', 'Payment gateway'])
    expect(loaded.documentState.nextThreatNumber).toBe(4)
    expect(loaded.documentState.nextCountermeasureNumber).toBe(3)
    expect(loaded.hiddenBlueprintCount).toBe(0)
    expect(loaded.hiddenElementCount).toBe(0)
  })

  it('exports the reopened model to the same document', () => {
    const first = exportDocument(sampleModel())
    const loaded = deserializeCycloneDxToGuest(first.json)
    const second = exportDocument({
      title: loaded.title,
      nodes: loaded.nodes,
      edges: loaded.edges,
      threats: loaded.threats,
      countermeasures: loaded.countermeasures,
      systemContext: loaded.systemContext,
      notationStyle: loaded.notationStyle,
      documentState: loaded.documentState,
    })
    expect(canonicalLines(second.document as Record<string, unknown>)).toEqual(canonicalLines(first.document as Record<string, unknown>))
    expect(second.version).toBe(first.version)
  })
})

// ---------------------------------------------------------------------------
// 3. Identity: serial number kept, version raised when the content changed
// ---------------------------------------------------------------------------

describeWithBackend('identity', () => {
  it('keeps the serial number across saves and raises the version only on a change', () => {
    const state = stateWithCounters()
    const first = exportDocument({ documentState: state })
    expect(first.document.serialNumber).toBe(state.serialNumber)
    expect(first.version).toBe(1)

    const saved = { ...state, version: first.version, exportDigest: first.digest }
    const unchanged = exportDocument({ documentState: saved })
    expect(unchanged.version).toBe(1)
    expect(unchanged.document.serialNumber).toBe(state.serialNumber)

    const changed = exportDocument({ documentState: saved, nodes: [makeNode('p1', 'process', 'Web')] })
    expect(changed.version).toBe(2)
  })

  it('opening a file is editing that document: the version does not move on an unchanged save', () => {
    const first = exportDocument(sampleModel())
    const loaded = deserializeCycloneDxToGuest(first.json)
    expect(loaded.documentState.serialNumber).toBe(first.document.serialNumber)
    expect(loaded.documentState.version).toBe(1)
    const resaved = exportDocument({ ...sampleModel(), nodes: loaded.nodes, edges: loaded.edges, threats: loaded.threats, countermeasures: loaded.countermeasures, systemContext: loaded.systemContext, documentState: loaded.documentState })
    expect(resaved.version).toBe(1)
    const edited = exportDocument({ ...sampleModel(), nodes: loaded.nodes, edges: loaded.edges, threats: loaded.threats.slice(1), countermeasures: [], systemContext: loaded.systemContext, documentState: loaded.documentState })
    expect(edited.version).toBe(2)
  })

  it('gives a file without a valid serial number a fresh one, with a warning', () => {
    const loaded = deserializeCycloneDxToGuest(JSON.stringify({ specFormat: 'CycloneDX', specVersion: '2.0', serialNumber: 'urn:uuid:test', blueprints: [{ name: 'X', modelTypes: ['data-flow'] }] }))
    expect(loaded.documentState.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/)
    expect(loaded.warnings.some((warning) => warning.includes('Serial number'))).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// 4. The shared fixture: a backend export opens and round trips
// ---------------------------------------------------------------------------

/**
 * The guest editor fills the canvas nodes with the blueprint's values (kind,
 * description, trust level) so the user sees them. The fixture's canvas was
 * built by hand and lacks those keys, so the comparison keeps, on each
 * guest canvas node, only the data keys the fixture's node has.
 */
function withCanvasKeysOf(guest: CycloneDxDocument, fixture: Record<string, unknown>): CycloneDxDocument {
  const copy: CycloneDxDocument = JSON.parse(JSON.stringify(guest))
  const decode = (document: Record<string, unknown>) => {
    const blueprint = (document.blueprints as Record<string, unknown>[])[0]
    const visualization = (blueprint.visualizations as Record<string, unknown>[]).find((entry) => (entry.attachment as { mediaType?: string } | undefined)?.mediaType === 'application/vnd.precogly.dfd+json')!
    const attachment = visualization.attachment as { content: string }
    return { attachment, canvas: JSON.parse(Buffer.from(attachment.content, 'base64').toString('utf8')) }
  }
  const fixtureCanvas = decode(fixture).canvas
  const guestSide = decode(copy as unknown as Record<string, unknown>)
  for (const node of guestSide.canvas.nodes) {
    const original = fixtureCanvas.nodes.find((candidate: { id: string }) => candidate.id === node.id)
    if (!original) continue
    for (const key of Object.keys(node.data)) {
      if (!(key in original.data)) delete node.data[key]
    }
  }
  guestSide.attachment.content = Buffer.from(JSON.stringify(guestSide.canvas), 'utf8').toString('base64')
  return copy
}

describeWithBackend('shared fixture', () => {
  it('opens the backend export with the right threats, targets and numbers', () => {
    const fixture = readReferenceFixture()
    const loaded = deserializeCycloneDxToGuest(JSON.stringify(fixture))
    expect(loaded.title).toBe('Reference model')
    expect(loaded.warnings.some((warning) => warning.startsWith('Schema'))).toBe(false)
    // The fixture's canvas shows two of its elements; the rest travel hidden.
    expect(loaded.nodes.map((node) => node.id)).toEqual(['z1', 'n1'])
    // 4 assets, 1 data store, 2 zones, 2 boundaries, 3 flows
    expect(loaded.hiddenElementCount).toBe(12)
    expect(loaded.warnings.some((warning) => warning.includes('12 elements of the blueprint are not on the diagram'))).toBe(true)

    expect(loaded.threats.map((threat) => [threat.number, threat.name, threat.level, threat.status])).toEqual([
      [1, 'SQL injection', 'high', 'accept'],
      [2, 'Backup theft', 'high', 'open'],
      [3, 'Boundary crossing', 'low', 'open'],
    ])
    expect(loaded.threats[0].targets).toEqual([{ id: 'n1', type: 'component' }])
    expect(loaded.threats[0].hiddenTargetRefs).toEqual(['flow-2'])
    expect(loaded.threats[0].category).toBe('tampering')
    expect(loaded.threats[0].decisionRationale).toBe('Accepted for now')
    expect(loaded.threats[1]).toMatchObject({ wholeSystem: true, targets: [], hiddenTargetRefs: [] })
    expect(loaded.threats[2]).toMatchObject({ wholeSystem: false, targets: [], hiddenTargetRefs: ['boundary-1'] })
    expect(loaded.countermeasures.map((countermeasure) => [countermeasure.number, countermeasure.name, countermeasure.threatIds.length])).toEqual([
      [1, 'Parameterised queries', 1],
      [2, 'Security training', 1],
    ])
    expect(loaded.countermeasures[0].targets).toEqual([{ id: 'n1', type: 'component' }])
    expect(loaded.countermeasures[0].hiddenTargetRefs).toEqual(['flow-2'])
    expect(loaded.countermeasures[1]).toMatchObject({ controlFunction: [], controlNature: '' })
    expect(loaded.documentState).toMatchObject({ serialNumber: fixture.serialNumber, version: 1, nextThreatNumber: 4, nextCountermeasureNumber: 3 })
    expect(loaded.systemContext.systemInfo.criticality).toBe('medium')
    expect(loaded.systemContext.dataAssets[0]).toMatchObject({ name: 'Card records', classification: 'confidential', confidentiality: 'high', availability: 'low', complianceTags: ['PCI DSS'] })
    expect(loaded.systemContext.assumptions[0]).toMatchObject({ description: 'TLS everywhere', validity: 'verified', topic: 'security' })
    expect(loaded.systemContext.outOfScopeItems).toEqual([{ id: expect.any(String), name: 'Mainframe', reason: 'Separate model' }])
  })

  it('writes the fixture back as it came, with everything it does not model as passthrough', () => {
    const fixture = readReferenceFixture()
    const loaded = deserializeCycloneDxToGuest(JSON.stringify(fixture))
    const result = buildGuestDocument({
      title: loaded.title,
      nodes: loaded.nodes,
      edges: loaded.edges,
      threats: loaded.threats,
      countermeasures: loaded.countermeasures,
      systemContext: loaded.systemContext,
      notationStyle: loaded.notationStyle,
      documentState: loaded.documentState,
    })
    assertValidTmBom(result.document, 'fixture re-export')
    expect(result.warnings).toEqual([])
    expect(result.version).toBe(1)
    const document = result.document

    // Passthrough: risks, business objectives, standards, use cases, the review block, actors, relationships
    expect(document.risks).toEqual(fixture.risks)
    expect(document.definitions).toEqual(fixture.definitions)
    const fixtureBlueprint = (fixture.blueprints as Record<string, unknown>[])[0]
    const blueprint = document.blueprints![0]
    expect(blueprint.metadata).toEqual(fixtureBlueprint.metadata)
    expect(blueprint.actors).toEqual(fixtureBlueprint.actors)
    expect(blueprint.relationships).toEqual(fixtureBlueprint.relationships)
    expect(document.threats?.methodologies).toEqual((fixture.threats as Record<string, unknown>).methodologies)
    expect(document.threats?.scenarios?.[1].likelihood).toEqual(((fixture.threats as Record<string, unknown>).scenarios as Record<string, unknown>[])[1].likelihood)
    expect(document.threats?.scenarios?.[1].impact).toEqual(((fixture.threats as Record<string, unknown>).scenarios as Record<string, unknown>[])[1].impact)
    expect(blueprint.assumptions?.[0]).toMatchObject({ owner: 'party-user-1', relatedAssets: ['asset-2'], validationMethod: 'Config review' })
    expect(document.metadata?.component).toEqual((fixture.metadata as Record<string, unknown>).component)
    expect(document.properties).toEqual(fixture.properties)

    // The whole document, canonicalised as the backend compares two exports.
    expect(canonicalLines(withCanvasKeysOf(document, fixture) as unknown as Record<string, unknown>)).toEqual(canonicalLines(fixture))
  })
})

// ---------------------------------------------------------------------------
// 5. Numbers (M12)
// ---------------------------------------------------------------------------

describeWithBackend('numbers', () => {
  function documentWithThreat(number: number, nextNumber?: number) {
    return {
      specFormat: 'CycloneDX',
      specVersion: '2.0',
      serialNumber: 'urn:uuid:11111111-2222-4333-8444-555555555555',
      version: 3,
      metadata: { component: { type: 'application', 'bom-ref': 'sys', name: 'X' } },
      blueprints: [{ 'bom-ref': 'bp', name: 'X', modelTypes: ['data-flow'], assets: [{ 'bom-ref': 'a1', name: 'Web', type: 'process' }] }],
      threats: {
        threats: [{ 'bom-ref': 'threat-custom-1', name: 'Seven' }],
        scenarios: [{ 'bom-ref': 's1', name: 'Seven', threats: ['threat-custom-1'], affectedAssets: ['a1'], riskScore: { level: 'low' }, properties: [{ name: 'precogly:number', value: String(number) }] }],
      },
      ...(nextNumber !== undefined ? { properties: [{ name: 'precogly:next-threat-number', value: String(nextNumber) }] } : {}),
    }
  }

  it('keeps T7 as T7 and sets the counter past the highest number seen', () => {
    const loaded = deserializeCycloneDxToGuest(JSON.stringify(documentWithThreat(7)))
    expect(loaded.threats[0].number).toBe(7)
    expect(loaded.documentState.nextThreatNumber).toBe(8)
    expect(loaded.documentState.version).toBe(3)
    const result = buildGuestDocument({ title: loaded.title, nodes: loaded.nodes, edges: loaded.edges, threats: loaded.threats, countermeasures: [], systemContext: loaded.systemContext, documentState: loaded.documentState })
    expect(result.document.threats?.scenarios?.[0].properties?.[0]).toEqual({ name: 'precogly:number', value: '7' })
    expect(result.document.properties?.[0]).toEqual({ name: 'precogly:next-threat-number', value: '8' })
  })

  it('takes the file counter when it is past the highest number', () => {
    const loaded = deserializeCycloneDxToGuest(JSON.stringify(documentWithThreat(7, 12)))
    expect(loaded.documentState.nextThreatNumber).toBe(12)
  })

  it('never hands a deleted number out again after a save and reopen', () => {
    const model = sampleModel()
    const first = exportDocument(model)
    const loaded = deserializeCycloneDxToGuest(first.json)
    // Delete the highest threat (T3) and save.
    const remaining = loaded.threats.filter((threat) => threat.number !== 3)
    const second = exportDocument({ ...model, nodes: loaded.nodes, edges: loaded.edges, threats: remaining, countermeasures: loaded.countermeasures.map((countermeasure) => ({ ...countermeasure, threatIds: countermeasure.threatIds.filter((id) => id !== loaded.threats[2].id) })).filter((countermeasure) => countermeasure.threatIds.length > 0), systemContext: loaded.systemContext, documentState: loaded.documentState })
    expect(second.document.properties?.[0]).toEqual({ name: 'precogly:next-threat-number', value: '4' })
    const reopened = deserializeCycloneDxToGuest(second.json)
    expect(Math.max(...reopened.threats.map((threat) => threat.number))).toBe(2)
    expect(reopened.documentState.nextThreatNumber).toBe(4)
  })

  it('renumbers a duplicate with a warning and numbers unnumbered scenarios in document order', () => {
    const base = documentWithThreat(2)
    base.threats.scenarios.push(
      { 'bom-ref': 's2', name: 'Dup', threats: ['threat-custom-1'], affectedAssets: ['a1'], riskScore: { level: 'low' }, properties: [{ name: 'precogly:number', value: '2' }] },
      { 'bom-ref': 's3', name: 'None', threats: ['threat-custom-1'], affectedAssets: ['a1'], riskScore: { level: 'low' }, properties: [] },
    )
    const loaded = deserializeCycloneDxToGuest(JSON.stringify(base))
    expect(loaded.threats.map((threat) => threat.number)).toEqual([2, 3, 4])
    expect(loaded.warnings.some((warning) => warning.includes('number 2 is taken'))).toBe(true)
    expect(loaded.documentState.nextThreatNumber).toBe(5)
  })
})

// ---------------------------------------------------------------------------
// 6. Further blueprints are kept (G8, L10)
// ---------------------------------------------------------------------------

describeWithBackend('extra blueprints', () => {
  it('edits the first blueprint and writes the others back unchanged', () => {
    const second = { 'bom-ref': 'bp-2', name: 'Plant network view', modelTypes: ['network'], assets: [{ 'bom-ref': 'plc', name: 'PLC', type: 'device' }] }
    const base = {
      specFormat: 'CycloneDX',
      specVersion: '2.0',
      serialNumber: 'urn:uuid:11111111-2222-4333-8444-555555555555',
      version: 1,
      metadata: { component: { type: 'application', 'bom-ref': 'sys', name: 'X' } },
      blueprints: [
        { 'bom-ref': 'bp-1', name: 'Main', modelTypes: ['data-flow'], assets: [{ 'bom-ref': 'a1', name: 'Web', type: 'process' }] },
        second,
      ],
      threats: {
        threats: [{ 'bom-ref': 'threat-custom-1', name: 'Command injection' }],
        scenarios: [{ 'bom-ref': 's1', name: 'Command injection', threats: ['threat-custom-1'], affectedAssets: ['a1', 'plc'], riskScore: { level: 'high' } }],
      },
    }
    const loaded = deserializeCycloneDxToGuest(JSON.stringify(base))
    expect(loaded.hiddenBlueprintCount).toBe(1)
    expect(loaded.warnings).toContain('This file has 1 more blueprint. It is not shown here and is kept when you save.')
    expect(loaded.threats[0].targets).toHaveLength(1)
    expect(loaded.threats[0].hiddenTargetRefs).toEqual(['plc'])
    expect(loaded.threats[0].hiddenBlueprintTargetCount).toBe(1)
    const result = buildGuestDocument({ title: loaded.title, nodes: loaded.nodes, edges: loaded.edges, threats: loaded.threats, countermeasures: [], systemContext: loaded.systemContext, documentState: loaded.documentState })
    assertValidTmBom(result.document, 'two blueprints')
    expect(result.document.blueprints).toHaveLength(2)
    expect(result.document.blueprints![1]).toEqual(second)
    expect(result.document.threats?.scenarios?.[0].affectedAssets).toEqual(['a1', 'plc'])
  })
})

// ---------------------------------------------------------------------------
// 7. The deletion rule (H9) and the derived status
// ---------------------------------------------------------------------------

describeWithBackend('deletion rule', () => {
  it('deletes a threat with its last target, keeps multi-target and whole-system threats', () => {
    const single = makeThreat({ name: 'Single', targets: [{ id: 'api', type: 'component' }] })
    const multi = makeThreat({ name: 'Multi', targets: [{ id: 'api', type: 'component' }, { id: 'db', type: 'component' }] })
    const whole = makeThreat({ name: 'Whole', wholeSystem: true })
    const hidden = makeThreat({ name: 'Hidden', targets: [{ id: 'api', type: 'component' }], hiddenTargetRefs: ['plc'], hiddenBlueprintTargetCount: 1 })
    const linkedToSingle = makeCountermeasure({ name: 'Only single', threatIds: [single.id], targets: [{ id: 'api', type: 'component' }] })
    const linkedToBoth = makeCountermeasure({ name: 'Both', threatIds: [single.id, multi.id] })
    const result = removeDiagramElements([single, multi, whole, hidden], [linkedToSingle, linkedToBoth], new Set(['api']))
    expect(result.removedThreatIds).toEqual([single.id])
    expect(result.threats.map((threat) => threat.name)).toEqual(['Multi', 'Whole', 'Hidden'])
    expect(result.threats[0].targets).toEqual([{ id: 'db', type: 'component' }])
    expect(result.threats[0].wholeSystem).toBe(false)
    expect(result.threats[2].targets).toEqual([])
    expect(result.removedCountermeasureIds).toEqual([linkedToSingle.id])
    expect(result.countermeasures).toEqual([{ ...linkedToBoth, threatIds: [multi.id] }])
  })

  it('removes a countermeasure that loses its last threat', () => {
    const threat = makeThreat({ name: 'T', wholeSystem: true })
    const other = makeThreat({ name: 'U', wholeSystem: true })
    const only = makeCountermeasure({ name: 'Only', threatIds: [threat.id] })
    const shared = makeCountermeasure({ name: 'Shared', threatIds: [threat.id, other.id] })
    const result = removeThreats([threat, other], [only, shared], new Set([threat.id]))
    expect(result.threats).toEqual([other])
    expect(result.countermeasures).toEqual([{ ...shared, threatIds: [other.id] }])
  })

  it('derives the threat status from the linked controls as the backend does', () => {
    const threat = makeThreat({ name: 'T', wholeSystem: true })
    expect(deriveThreatStatus(threat, [])).toBe('exposed')
    expect(deriveThreatStatus(threat, [makeCountermeasure({ name: 'new', threatIds: [threat.id] })])).toBe('addressable')
    expect(deriveThreatStatus(threat, [makeCountermeasure({ name: 'done', threatIds: [threat.id], passthrough: { status: 'implemented' } })])).toBe('mitigated')
    expect(deriveThreatStatus(threat, [makeCountermeasure({ name: 'gap', threatIds: [threat.id], passthrough: { status: { name: 'gap' } } })])).toBe('exposed')
  })
})

// ---------------------------------------------------------------------------
// 8. Lenient import
// ---------------------------------------------------------------------------

describeWithBackend('lenient import', () => {
  it('lays out a third-party file without a visualization and keeps custom types for the file', () => {
    const document = {
      specFormat: 'CycloneDX',
      specVersion: '2.0',
      serialNumber: 'urn:uuid:11111111-2222-4333-8444-555555555555',
      version: 1,
      blueprints: [{
        name: 'Other tool',
        modelTypes: ['data-flow'],
        zones: [{ 'bom-ref': 'z1', name: 'Inside', type: { name: 'Blast radius' } }],
        assets: [
          { 'bom-ref': 'a1', name: 'Web', type: 'process', zone: 'z1' },
          { 'bom-ref': 'a2', name: 'User', type: 'actor' },
        ],
        dataStores: [{ 'bom-ref': 'd1', name: 'Store', type: 'relational', zone: 'z1' }],
        flows: [{ 'bom-ref': 'f1', name: 'Browse', type: 'data', source: 'a2', destination: 'a1', authentication: ['none', 'basic'] }],
      }],
      threats: {
        threats: [{ 'bom-ref': 't1', name: 'Spoof', categories: [{ taxonomy: 'STRIDE', category: 'spoofing' }] }],
        scenarios: [{ 'bom-ref': 's1', name: 'Spoof', threats: ['t1'], affectedAssets: ['a2', 'nowhere'], riskScore: { level: 'medium' } }],
      },
      controls: [{ 'bom-ref': 'c1', name: 'MFA', category: 'preventive', status: 'implemented' }],
    }
    const loaded = deserializeCycloneDxToGuest(JSON.stringify(document))
    expect(loaded.nodes.map((node) => node.type)).toEqual(['trustZone', 'process', 'humanActor', 'datastore'])
    expect(loaded.nodes[1].parentId).toBe(loaded.nodes[0].id)
    expect(loaded.nodes[0].data.zoneType).toBeUndefined()
    expect(loaded.edges).toHaveLength(1)
    expect(loaded.edges[0].data?.authentication).toEqual([])
    expect(loaded.threats[0]).toMatchObject({ number: 1, category: 'spoofing', targets: [{ id: loaded.nodes[2].id, type: 'component' }], hiddenTargetRefs: ['nowhere'] })
    // The fallback from threat.mitigations applies when precogly:mitigates is absent: none here.
    expect(loaded.countermeasures[0]).toMatchObject({ number: 1, threatIds: [], controlFunction: ['preventive'], controlNature: '' })
    expect(loaded.warnings).toEqual(expect.arrayContaining([
      expect.stringContaining("Zone 'Inside': type 'Blast radius' is not a CycloneDX value"),
      expect.stringContaining("Flow 'Browse': authentication mixes 'none'"),
      expect.stringContaining("Threat 'Spoof': 1 target(s) are not on this diagram"),
    ]))

    const result = buildGuestDocument({ title: loaded.title, nodes: loaded.nodes, edges: loaded.edges, threats: loaded.threats, countermeasures: loaded.countermeasures, systemContext: loaded.systemContext, documentState: loaded.documentState })
    expect(result.document.blueprints![0].zones![0].type).toEqual({ name: 'Blast radius' })
    // The ref that pointed at nothing is repaired on export, with a warning.
    expect(result.document.threats?.scenarios?.[0].affectedAssets).toEqual(['a2'])
    expect(result.warnings.some((warning) => warning.includes('affectedAssets'))).toBe(true)
    expect(result.document.controls?.[0].status).toBe('implemented')
    assertValidTmBom(result.document, 'third-party round trip')
  })

  it('reports a decoded canvas that disagrees with the blueprint on a name', () => {
    const first = exportDocument(sampleModel())
    const document = JSON.parse(first.json)
    document.blueprints[0].assets.find((asset: { name: string }) => asset.name === 'API').name = 'Gateway'
    const loaded = deserializeCycloneDxToGuest(JSON.stringify(document))
    expect(loaded.nodes.find((node) => node.id === 'api')?.data.label).toBe('Gateway')
    expect(loaded.warnings).toContain("Diagram element 'API' renamed to 'Gateway' to match the blueprint.")
  })
})

// ---------------------------------------------------------------------------
// 9. Error handling
// ---------------------------------------------------------------------------

describeWithBackend('error handling', () => {
  it('rejects invalid JSON', () => {
    expect(() => deserializeCycloneDxToGuest('not json {')).toThrow('Could not parse file as JSON')
  })

  it('rejects non-object JSON', () => {
    expect(() => deserializeCycloneDxToGuest('"just a string"')).toThrow('The file content must be a JSON object')
  })

  it('rejects missing specFormat', () => {
    expect(() => deserializeCycloneDxToGuest('{"version": 1}')).toThrow("must have a 'specFormat' field")
  })

  it('rejects wrong specFormat', () => {
    expect(() => deserializeCycloneDxToGuest(JSON.stringify({ specFormat: 'SPDX', specVersion: '2.0' }))).toThrow("Found specFormat 'SPDX' but expected 'CycloneDX'")
  })

  it('rejects unsupported version', () => {
    expect(() => deserializeCycloneDxToGuest(JSON.stringify({ specFormat: 'CycloneDX', specVersion: '1.5' }))).toThrow("Unsupported CycloneDX version '1.5'")
  })

  it('handles missing version gracefully', () => {
    expect(() => deserializeCycloneDxToGuest(JSON.stringify({ specFormat: 'CycloneDX' }))).toThrow("Unsupported CycloneDX version 'unknown'")
  })

  it('canonical() tokenises refs in document order', () => {
    const left = canonical({ blueprints: [{ 'bom-ref': 'a', zones: [{ 'bom-ref': 'z', parent: 'a' }] }] })
    const right = canonical({ blueprints: [{ 'bom-ref': 'x', zones: [{ 'bom-ref': 'y', parent: 'x' }] }] })
    expect(left).toEqual(right)
  })
})
