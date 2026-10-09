#!/usr/bin/env node
/**
 * Writes `src/features/guest-editor/lib/cyclonedx-spec.generated.ts` from the
 * backend's one source for spec values and `precogly:` property names (plan
 * section 9.6, G9):
 *
 *   backend/apps/threat_models/tmbom/properties.py   the property registry
 *   backend/apps/threat_models/tmbom/spec_values.py  the enums and value maps
 *   backend/apps/systems/crossing.py                 the lists spec_values re-exports
 *
 * The Python modules are read as text and their module-level literal
 * assignments (strings, numbers, tuples, lists, dicts, enum members and
 * `PrecoglyProperty(...)` calls) are parsed by the small literal parser below.
 * Anything that is not a plain literal (a comprehension, a function) is
 * skipped on purpose. A vitest test (`__tests__/cyclonedx-spec.test.ts`)
 * regenerates the file in memory and fails when the committed one differs,
 * so drift between the backend and the guest editor is caught.
 *
 * Run from `frontend/`: `node scripts/generate-cyclonedx-spec.mjs`
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url))
export const DEFAULT_BACKEND_DIR = resolve(SCRIPT_DIR, '..', '..', 'backend')
export const OUTPUT_PATH = resolve(
  SCRIPT_DIR,
  '..',
  'src',
  'features',
  'guest-editor',
  'lib',
  'cyclonedx-spec.generated.ts'
)

export const SOURCE_FILES = {
  properties: 'apps/threat_models/tmbom/properties.py',
  specValues: 'apps/threat_models/tmbom/spec_values.py',
  crossing: 'apps/systems/crossing.py',
}

// ---------------------------------------------------------------------------
// A parser for the Python literal subset the two modules use
// ---------------------------------------------------------------------------

class Unsupported extends Error {}

class PythonLiteralParser {
  constructor(source) {
    this.source = source
    this.position = 0
  }

  skipSpace() {
    for (;;) {
      const char = this.source[this.position]
      if (char === '#') {
        while (this.position < this.source.length && this.source[this.position] !== '\n') {
          this.position += 1
        }
      } else if (char === ' ' || char === '\n' || char === '\t' || char === '\r') {
        this.position += 1
      } else {
        return
      }
    }
  }

  peek() {
    this.skipSpace()
    return this.source[this.position]
  }

  expect(char) {
    this.skipSpace()
    if (this.source[this.position] !== char) {
      throw new Unsupported(`expected ${char} at ${this.position}`)
    }
    this.position += 1
  }

  parseValue() {
    const char = this.peek()
    if (char === '"' || char === "'") return this.parseStringSequence()
    if (char === '(') return this.parseSequence('(', ')')
    if (char === '[') return this.parseSequence('[', ']')
    if (char === '{') return this.parseDict()
    if (char === '*') throw new Unsupported('unpacking')
    if (/[0-9-]/.test(char)) return this.parseNumber()
    if (/[A-Za-z_]/.test(char)) return this.parseNameOrCall()
    throw new Unsupported(`unexpected ${char} at ${this.position}`)
  }

  parseStringSequence() {
    // Adjacent literals concatenate, as in Python ("a" "b").
    let value = this.parseString()
    for (;;) {
      const next = this.peek()
      if (next === '"' || next === "'") {
        value += this.parseString()
      } else {
        return value
      }
    }
  }

  parseString() {
    this.skipSpace()
    const quote = this.source[this.position]
    const triple = this.source.startsWith(quote.repeat(3), this.position)
    this.position += triple ? 3 : 1
    let value = ''
    for (;;) {
      if (this.position >= this.source.length) throw new Unsupported('unterminated string')
      const char = this.source[this.position]
      if (char === '\\') {
        const escaped = this.source[this.position + 1]
        value += escaped === 'n' ? '\n' : escaped === 't' ? '\t' : escaped
        this.position += 2
        continue
      }
      if (triple && this.source.startsWith(quote.repeat(3), this.position)) {
        this.position += 3
        return value
      }
      if (!triple && char === quote) {
        this.position += 1
        return value
      }
      value += char
      this.position += 1
    }
  }

  parseNumber() {
    this.skipSpace()
    const match = /^-?\d+(\.\d+)?/.exec(this.source.slice(this.position))
    if (!match) throw new Unsupported('number')
    this.position += match[0].length
    return Number(match[0])
  }

  parseNameOrCall() {
    this.skipSpace()
    const match = /^[A-Za-z_][A-Za-z0-9_.]*/.exec(this.source.slice(this.position))
    this.position += match[0].length
    const name = match[0]
    if (name === 'True') return true
    if (name === 'False') return false
    if (name === 'None') return null
    if (this.peek() === '(') {
      const args = this.parseSequence('(', ')')
      return { call: name, args }
    }
    return { name }
  }

  parseSequence(open, close) {
    this.expect(open)
    const items = []
    for (;;) {
      if (this.peek() === close) {
        this.position += 1
        return items
      }
      const value = this.parseValue()
      if (this.peek() === 'f' && this.source.startsWith('for', this.position)) {
        throw new Unsupported('comprehension')
      }
      items.push(value)
      if (this.peek() === ',') {
        this.position += 1
      } else if (this.peek() !== close) {
        throw new Unsupported(`expected , or ${close} at ${this.position}`)
      }
    }
  }

  parseDict() {
    this.expect('{')
    const entries = {}
    for (;;) {
      if (this.peek() === '}') {
        this.position += 1
        return entries
      }
      if (this.peek() === '*') throw new Unsupported('unpacking')
      const key = this.parseValue()
      if (this.peek() === 'f' && this.source.startsWith('for', this.position)) {
        throw new Unsupported('comprehension')
      }
      this.expect(':')
      const value = this.parseValue()
      if (this.peek() === 'f' && this.source.startsWith('for', this.position)) {
        throw new Unsupported('comprehension')
      }
      entries[typeof key === 'string' ? key : JSON.stringify(key)] = value
      if (this.peek() === ',') {
        this.position += 1
      } else if (this.peek() !== '}') {
        throw new Unsupported(`expected , or } at ${this.position}`)
      }
    }
  }
}

/** Module-level `NAME = <literal>` assignments, in source order. */
export function parseModuleAssignments(source) {
  const assignments = new Map()
  const pattern = /^([A-Z][A-Z0-9_]*)(?::[^=\n]+)?\s*=\s*/gm
  let match
  while ((match = pattern.exec(source)) !== null) {
    const parser = new PythonLiteralParser(source)
    parser.position = match.index + match[0].length
    try {
      assignments.set(match[1], parser.parseValue())
    } catch (error) {
      if (!(error instanceof Unsupported)) throw error
    }
  }
  return assignments
}

/** The `NAME = "value"` members of every `class X(StrEnum)` in the module. */
export function parseStrEnums(source) {
  const enums = {}
  const classPattern = /^class (\w+)\(StrEnum\):\n((?:[ \t]+.*\n|\n)*)/gm
  let match
  while ((match = classPattern.exec(source)) !== null) {
    const members = {}
    const memberPattern = /^[ \t]+([A-Z][A-Z0-9_]*)\s*=\s*"([^"]*)"/gm
    let member
    while ((member = memberPattern.exec(match[2])) !== null) {
      members[member[1]] = member[2]
    }
    enums[match[1]] = members
  }
  return enums
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function tsLiteral(value, indent = '') {
  if (Array.isArray(value)) {
    return `[\n${value.map((item) => `${indent}  ${tsLiteral(item, `${indent}  `)},`).join('\n')}\n${indent}]`
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value)
    return `{\n${entries
      .map(([key, item]) => `${indent}  ${JSON.stringify(key)}: ${tsLiteral(item, `${indent}  `)},`)
      .join('\n')}\n${indent}}`
  }
  return JSON.stringify(value)
}

function isStringList(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function isStringMap(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.values(value).every((item) => typeof item === 'string')
  )
}

function isStringListMap(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.values(value).every(isStringList)
  )
}

function renderConstant(name, value) {
  if (isStringList(value)) return `export const ${name} = ${tsLiteral(value)} as const\n`
  if (isStringMap(value)) return `export const ${name}: Record<string, string> = ${tsLiteral(value)}\n`
  if (isStringListMap(value)) {
    return `export const ${name}: Record<string, readonly string[]> = ${tsLiteral(value)}\n`
  }
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return `export const ${name} = ${JSON.stringify(value)}\n`
  }
  return null
}

/** Resolve `{name: "X.Y"}` references to enum members or other constants. */
function resolveReferences(value, enums, constants) {
  if (Array.isArray(value)) return value.map((item) => resolveReferences(item, enums, constants))
  if (value !== null && typeof value === 'object') {
    if ('name' in value && Object.keys(value).length === 1) {
      const [owner, member] = value.name.split('.')
      if (member && enums[owner] && member in enums[owner]) return enums[owner][member]
      if (!member && constants.has(owner)) return constants.get(owner)
      if (!member && (owner === 'bool' || owner === 'int' || owner === 'str')) return owner
      throw new Error(`unresolved reference ${value.name}`)
    }
    if ('call' in value) return value
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, resolveReferences(item, enums, constants)])
    )
  }
  return value
}

export function generate(backendDir = DEFAULT_BACKEND_DIR) {
  const read = (relative) => readFileSync(resolve(backendDir, relative), 'utf8')
  const propertiesSource = read(SOURCE_FILES.properties)
  const specValuesSource = read(SOURCE_FILES.specValues)
  const crossingSource = read(SOURCE_FILES.crossing)

  const enums = parseStrEnums(propertiesSource)
  const crossing = parseModuleAssignments(crossingSource)
  const specValues = parseModuleAssignments(specValuesSource)
  const properties = parseModuleAssignments(propertiesSource)

  const constants = new Map()
  for (const source of [crossing, specValues]) {
    for (const [name, raw] of source) {
      if (name === '__ALL__') continue
      let value
      try {
        value = resolveReferences(raw, enums, constants)
      } catch {
        continue
      }
      if (value !== null && typeof value === 'object' && !Array.isArray(value) && 'call' in value) continue
      constants.set(name, value)
    }
  }

  const registryRaw = properties.get('REGISTRY')
  if (!Array.isArray(registryRaw)) throw new Error('REGISTRY not found in properties.py')
  const registry = registryRaw.map((entry) => {
    if (!entry || entry.call !== 'PrecoglyProperty') throw new Error('REGISTRY entry is not a PrecoglyProperty call')
    const [name, owner, valueType, description] = resolveReferences(entry.args, enums, constants)
    return { name, owner, valueType, description }
  })

  const lines = []
  lines.push('/**')
  lines.push(" * GENERATED FILE. Do not edit by hand: run `node scripts/generate-cyclonedx-spec.mjs`")
  lines.push(' * from `frontend/`.')
  lines.push(' *')
  lines.push(' * Mirrors the backend\'s one source for CycloneDX TM-BOM spec values and')
  lines.push(' * `precogly:` property names (plan section 9.6):')
  for (const relative of Object.values(SOURCE_FILES)) {
    lines.push(` *   backend/${relative}`)
  }
  lines.push(' *')
  lines.push(' * `__tests__/cyclonedx-spec.test.ts` regenerates this file in memory and')
  lines.push(' * fails when the committed copy differs.')
  lines.push(' */')
  lines.push('')
  lines.push('export interface PrecoglyPropertyEntry {')
  lines.push('  name: string')
  lines.push('  owner: string')
  lines.push('  valueType: string')
  lines.push('  description: string')
  lines.push('}')
  lines.push('')
  lines.push(`export const PROPERTY_PREFIX = ${JSON.stringify(constants.get('PROPERTY_PREFIX') ?? 'precogly:')}`)
  lines.push('')
  for (const [enumName, members] of Object.entries(enums)) {
    lines.push(`export const ${enumName.replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase()} = ${tsLiteral(members)} as const`)
    lines.push('')
  }
  lines.push('/** The `precogly:` property registry, in the order the backend declares it. */')
  lines.push(`export const PRECOGLY_PROPERTIES: readonly PrecoglyPropertyEntry[] = ${tsLiteral(registry)}`)
  lines.push('')
  for (const [name, value] of constants) {
    if (name === 'PROPERTY_PREFIX') continue
    const rendered = renderConstant(name, value)
    if (rendered) {
      lines.push(rendered)
    }
  }
  return `${lines.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd()}\n`
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (isMain) {
  const output = generate(process.argv[2] ? resolve(process.argv[2]) : DEFAULT_BACKEND_DIR)
  writeFileSync(OUTPUT_PATH, output)
  console.log(`wrote ${OUTPUT_PATH}`)
}
