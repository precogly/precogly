/**
 * The committed fixtures the guest editor's e2e specs and the backend
 * cross-check (`backend/apps/threat_models/tests/test_guest_editor_fixture.py`)
 * open. They are what the adapter writes for a model that touches every
 * slice the guest editor models, plus a copy of the shared backend fixture.
 *
 * Regenerate after changing the adapter on purpose:
 *   GUEST_WRITE_FIXTURES=1 npx vitest run src/features/guest-editor/__tests__/fixtures.test.ts
 * The test then also copies the guest export under the backend's fixtures.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { buildGuestDocument, deserializeCycloneDxToGuest, newDocumentState } from '../lib/cyclonedx-guest'
import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'
import type { GuestCountermeasure, GuestThreat } from '../types'
import { canonicalLines } from './tmbom-canonical'
import { BACKEND_AVAILABLE, assertValidTmBom, REFERENCE_FIXTURE_PATH, REPO_ROOT } from './tmbom-schema'

const E2E_FIXTURES = resolve(__dirname, 'e2e', 'fixtures')
const GUEST_EXPORT_PATH = resolve(__dirname, 'fixtures', 'guest-editor-export.cdx.json')
const BACKEND_COPY_PATH = resolve(REPO_ROOT, 'backend', 'apps', 'threat_models', 'tests', 'fixtures', 'tmbom', 'guest-editor-export.cdx.json')
const WRITE = process.env.GUEST_WRITE_FIXTURES === '1'

function node(id: string, type: string, label: string, position: { x: number; y: number }, data: Record<string, unknown> = {}, parentId?: string): DiagramNode {
  return { id, type, position, ...(parentId ? { parentId } : {}), data: { label, ...data }, ...(type === 'trustZone' ? { style: { width: 420, height: 300 } } : {}) } as DiagramNode
}

/** The model the e2e specs and the backend cross-check open: a web shop with two zones. */
function guestModel() {
  const nodes = [
    node('zone-internet', 'trustZone', 'Internet', { x: 40, y: 40 }, { zoneType: 'trust', trustLevel: 10, zoneColor: '#ef4444' }),
    node('zone-core', 'trustZone', 'Core network', { x: 520, y: 40 }, { zoneType: 'network', trustLevel: 80, zoneColor: '#22c55e' }),
    node('process-web', 'process', 'Web Server', { x: 40, y: 60 }, { description: 'Serves the shop', technology: 'nginx', kind: 'service' }, 'zone-core'),
    node('datastore-db', 'datastore', 'Database', { x: 240, y: 60 }, { dataStoreType: 'sql', dataSensitivity: 'confidential' }, 'zone-core'),
    node('actor-customer', 'humanActor', 'Customer', { x: 40, y: 80 }, { actorType: 'customer' }, 'zone-internet'),
    node('actor-psp', 'systemActor', 'Payment provider', { x: 40, y: 400 }, { systemType: 'api' }),
  ]
  const edges: DiagramEdge[] = [
    { id: 'flow-browse', type: 'dataFlow', source: 'actor-customer', target: 'process-web', animated: true, data: { label: 'Browse', flowType: 'data', protocol: 'HTTPS', port: 443, encrypted: true, authentication: ['session-cookie'], dataClassification: ['pii'], hasSensitiveData: true } } as DiagramEdge,
    { id: 'flow-query', type: 'dataFlow', source: 'process-web', target: 'datastore-db', animated: true, data: { label: 'Query', flowType: 'data', protocol: 'SQL', encrypted: false, authentication: ['basic'] } } as DiagramEdge,
    { id: 'flow-charge', type: 'dataFlow', source: 'process-web', target: 'actor-psp', animated: true, data: { label: 'Charge', flowType: 'message', encrypted: true, authentication: ['api-key'] } } as DiagramEdge,
    { id: 'boundary-edge', type: 'trustBoundary', source: 'zone-internet', target: 'zone-core', data: { label: 'Internet edge', boundaryType: 'trust', authenticationMethods: ['session-cookie'], accessControlMethods: ['rbac'], dataValidation: true, logging: true, rateLimit: '100 requests per second', accessTokenExpires: true, accessTokenTtl: 900, canUserLogout: true } } as DiagramEdge,
  ]
  const threats: GuestThreat[] = [
    { id: 'threat-sqli', number: 1, name: 'SQL Injection', description: 'Attacker injects SQL through the search form', level: 'high', category: 'tampering', status: 'mitigate', targets: [{ id: 'process-web', type: 'component' }, { id: 'flow-query', type: 'flow' }], wholeSystem: false, hiddenTargetRefs: [], hiddenBlueprintTargetCount: 0, createdAt: '2026-10-08T00:00:00.000Z' },
    { id: 'threat-session', number: 2, name: 'Session hijacking', description: 'Stolen session cookie reused from another network', level: 'medium', category: 'spoofing', status: 'open', targets: [{ id: 'boundary-edge', type: 'boundary' }, { id: 'flow-browse', type: 'flow' }], wholeSystem: false, hiddenTargetRefs: [], hiddenBlueprintTargetCount: 0, createdAt: '2026-10-08T00:00:00.000Z' },
    { id: 'threat-backups', number: 3, name: 'No backup tested', description: '', level: 'info', status: 'accept', decisionRationale: 'Backups are restored monthly by operations', targets: [], wholeSystem: true, hiddenTargetRefs: [], hiddenBlueprintTargetCount: 0, createdAt: '2026-10-08T00:00:00.000Z' },
    { id: 'threat-zone', number: 4, name: 'Lateral movement in the core network', description: '', level: 'low', category: 'elevation-of-privilege', status: 'open', targets: [{ id: 'zone-core', type: 'zone' }], wholeSystem: false, hiddenTargetRefs: [], hiddenBlueprintTargetCount: 0, createdAt: '2026-10-08T00:00:00.000Z' },
  ]
  const countermeasures: GuestCountermeasure[] = [
    { id: 'cm-validation', number: 1, threatIds: ['threat-sqli'], name: 'Input Validation', description: 'Validate and parameterise every query', controlFunction: ['preventive'], controlNature: 'technical', targets: [{ id: 'process-web', type: 'component' }], hiddenTargetRefs: [], createdAt: '2026-10-08T00:00:00.000Z' },
    { id: 'cm-tokens', number: 2, threatIds: ['threat-session', 'threat-sqli'], name: 'Short-lived tokens', description: 'Rotate session tokens and bind them to the client', controlFunction: ['preventive', 'detective'], controlNature: 'technical', targets: [], hiddenTargetRefs: [], createdAt: '2026-10-08T00:00:00.000Z' },
  ]
  const documentState = newDocumentState()
  documentState.serialNumber = 'urn:uuid:6f1c2a9e-4b7d-4c1e-9a2f-3d5e6f7a8b9c'
  documentState.nextThreatNumber = 5
  documentState.nextCountermeasureNumber = 3
  return {
    title: 'Web shop',
    nodes,
    edges,
    threats,
    countermeasures,
    systemContext: {
      session: { facilitator: 'Security Team', participants: ['Alice', 'Bob'], meetingDate: '2026-10-08' },
      systemInfo: { description: 'A small web shop with a hosted payment provider', criticality: 'high' as const },
      dataAssets: [{ id: 'da-cards', name: 'Customer records', description: 'Names, addresses and order history', classification: 'confidential', confidentiality: 'high' as const, integrity: 'medium' as const, availability: 'low' as const, complianceTags: ['GDPR'], dataSensitivity: ['pii'] }],
      assumptions: [{ id: 'assumption-tls', description: 'TLS is terminated at the edge and re-encrypted inside', validity: 'verified' as const, topic: 'security' }],
      outOfScopeItems: [{ id: 'oos-psp', name: 'Payment provider', reason: 'Assessed by the provider' }],
    },
    notationStyle: 'yourdon' as const,
    documentState,
  }
}

describe.skipIf(!BACKEND_AVAILABLE)('fixtures', () => {
  it('the guest export fixture is what the adapter writes for the sample model', () => {
    const result = buildGuestDocument(guestModel())
    assertValidTmBom(result.document, 'guest export fixture')
    expect(result.warnings).toEqual([])
    // A fixed timestamp keeps the committed file stable.
    const document = { ...result.document, metadata: { ...result.document.metadata, timestamp: '2026-10-08T12:00:00.000Z' } }
    const json = `${JSON.stringify(document, null, 2)}\n`
    if (WRITE) {
      mkdirSync(resolve(__dirname, 'fixtures'), { recursive: true })
      writeFileSync(GUEST_EXPORT_PATH, json)
      writeFileSync(resolve(E2E_FIXTURES, 'valid-diagram.cdx.json'), json)
      writeFileSync(BACKEND_COPY_PATH, json)
    }
    expect(existsSync(GUEST_EXPORT_PATH)).toBe(true)
    expect(canonicalLines(JSON.parse(readFileSync(GUEST_EXPORT_PATH, 'utf8')))).toEqual(canonicalLines(document as Record<string, unknown>))
    expect(readFileSync(resolve(E2E_FIXTURES, 'valid-diagram.cdx.json'), 'utf8')).toBe(readFileSync(GUEST_EXPORT_PATH, 'utf8'))
    expect(readFileSync(BACKEND_COPY_PATH, 'utf8')).toBe(readFileSync(GUEST_EXPORT_PATH, 'utf8'))
  })

  it('the guest export fixture opens without warnings', () => {
    const loaded = deserializeCycloneDxToGuest(readFileSync(GUEST_EXPORT_PATH, 'utf8'))
    expect(loaded.warnings).toEqual([])
    expect(loaded.threats.map((threat) => threat.number)).toEqual([1, 2, 3, 4])
    expect(loaded.countermeasures[1].threatIds).toHaveLength(2)
  })

  it('the e2e backend-export fixture is the shared reference fixture', () => {
    const reference = readFileSync(REFERENCE_FIXTURE_PATH, 'utf8')
    const target = resolve(E2E_FIXTURES, 'backend-export.cdx.json')
    if (WRITE) writeFileSync(target, reference)
    expect(readFileSync(target, 'utf8')).toBe(reference)
  })
})
