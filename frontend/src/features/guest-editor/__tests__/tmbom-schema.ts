/**
 * Test-only validation of a TM-BOM document against the pinned CycloneDX
 * 2.0 schema (decision D17: no run-time check in the editor).
 *
 * The schema is read from the backend package, so the frontend never ships
 * it. Two checks, as `backend/apps/threat_models/tmbom/validation.py`:
 * JSON Schema errors and ref integrity (unique bom-refs, every reference
 * resolving to one).
 */

import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import Ajv2020, { type ValidateFunction } from 'ajv/dist/2020'
import addFormats from 'ajv-formats'

export const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..')
export const SCHEMA_PATH = resolve(REPO_ROOT, 'backend', 'apps', 'threat_models', 'tmbom', 'schema', 'cyclonedx-2.0-bundled.schema.json')
export const REFERENCE_FIXTURE_PATH = resolve(REPO_ROOT, 'backend', 'apps', 'threat_models', 'tests', 'fixtures', 'tmbom', 'reference-model.cdx.json')

/**
 * The schema and the shared fixture live in the backend tree. The frontend
 * container mounts `frontend/src` only, so the tests that need them run on a
 * full checkout (CI, the host) and skip inside the container.
 */
export const BACKEND_AVAILABLE = existsSync(SCHEMA_PATH) && existsSync(REFERENCE_FIXTURE_PATH)

let validator: ValidateFunction | null = null

function schemaValidator(): ValidateFunction {
  if (validator === null) {
    const schema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf8'))
    // The backend validates without a format checker (jsonschema's default),
    // so formats are a bonus here; ajv-formats has no iri-reference or
    // idn-email, which are accepted as any string.
    const ajv = new Ajv2020({ allErrors: true, strict: false, logger: false })
    addFormats(ajv)
    ajv.addFormat('iri-reference', true)
    ajv.addFormat('idn-email', true)
    // The bundled schema still points at four sibling files (the SPDX license
    // list, the behavior taxonomy, the cryptography enums) that the pinned
    // package does not carry and the backend validator never reaches
    // (jsonschema resolves lazily). Ajv compiles eagerly: those values pass.
    ajv.addSchema({ type: 'string' }, 'https://cyclonedx.org/schema/spdx.schema.json')
    ajv.addSchema({}, 'https://cyclonedx.org/schema/behavior-taxonomy.schema.json')
    ajv.addSchema(
      { definitions: { algorithmFamiliesEnum: {}, ellipticCurvesEnum: {}, protocolFamiliesEnum: {} } },
      'https://cyclonedx.org/schema/cryptography-defs.schema.json'
    )
    validator = ajv.compile(schema)
  }
  return validator
}

export function schemaErrors(document: unknown): string[] {
  const validate = schemaValidator()
  if (validate(document)) return []
  return (validate.errors ?? []).map((error) => `${error.instancePath || '<document>'}: ${error.message ?? ''} ${JSON.stringify(error.params)}`)
}

// The backend's REF_KEYS (tmbom/validation.py).
const REF_KEYS = new Set([
  'source', 'destination', 'zone', 'parent', 'threats', 'affectedAssets', 'actor', 'threatProfile',
  'appliesTo', 'implementedBy', 'satisfies', 'mitigations', 'relatedThreats',
  'relatedBusinessObjectives', 'controls', 'boundary', 'threatsAtBoundary', 'controlsAtBoundary',
  'zones', 'relatedAssets', 'dataSets', 'dataStore', 'excludedComponents', 'ref', 'dependsOn',
  'contains', 'aggregates', 'associates', 'composes', 'generalizes', 'realizes', 'serves', 'owner',
  'reviewer', 'approver', 'party', 'affects', 'addresses', 'targets',
])

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function refIntegrityErrors(document: unknown): string[] {
  const findings: string[] = []
  const seen = new Map<string, string>()
  const refs = new Set<string>()
  const collect = (node: unknown, path: string) => {
    if (Array.isArray(node)) {
      node.forEach((item, index) => collect(item, `${path}/${index}`))
      return
    }
    if (!isObject(node)) return
    const ref = node['bom-ref']
    if (typeof ref === 'string') {
      if (seen.has(ref)) findings.push(`${path}/bom-ref: duplicate bom-ref '${ref}', first seen at ${seen.get(ref)}`)
      else seen.set(ref, path)
      refs.add(ref)
    }
    for (const [key, value] of Object.entries(node)) collect(value, path ? `${path}/${key}` : key)
  }
  collect(document, '')
  const check = (value: unknown, path: string) => {
    if (typeof value === 'string') {
      if (value && !value.startsWith('urn:cdx:') && !refs.has(value)) findings.push(`${path}: reference '${value}' resolves to nothing`)
    } else if (Array.isArray(value)) {
      value.forEach((item, index) => {
        if (typeof item === 'string') check(item, `${path}/${index}`)
      })
    }
  }
  const walk = (node: unknown, path: string) => {
    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, `${path}/${index}`))
      return
    }
    if (!isObject(node)) return
    for (const [key, value] of Object.entries(node)) {
      const child = path ? `${path}/${key}` : key
      if (REF_KEYS.has(key) && (typeof value === 'string' || Array.isArray(value))) check(value, child)
      walk(value, child)
    }
  }
  walk(document, '')
  return findings
}

/** Zero schema errors and zero ref errors, as the backend's `assert_valid_tmbom`. */
export function assertValidTmBom(document: unknown, context = 'document'): void {
  const findings = [...schemaErrors(document), ...refIntegrityErrors(document)]
  if (findings.length > 0) {
    throw new Error(`TM-BOM ${context} has ${findings.length} error(s):\n  - ${findings.join('\n  - ')}`)
  }
}

export function readReferenceFixture(): Record<string, unknown> {
  return JSON.parse(readFileSync(REFERENCE_FIXTURE_PATH, 'utf8'))
}
