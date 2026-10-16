import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { PRECOGLY_PROPERTIES, PROPERTY_PREFIX, ZONE_TYPES } from '../lib/cyclonedx-spec.generated'
import { BACKEND_AVAILABLE, REPO_ROOT } from './tmbom-schema'

const BACKEND_DIR = resolve(REPO_ROOT, 'backend')
const GENERATED_PATH = resolve(__dirname, '..', 'lib', 'cyclonedx-spec.generated.ts')

interface Generator {
  generate: (backendDir: string) => string
  SOURCE_FILES: Record<'properties' | 'specValues' | 'crossing', string>
}

/** The generator is a plain ES module outside `src`; it is loaded at run time so a checkout without `scripts/` skips cleanly. */
async function loadGenerator(): Promise<Generator> {
  return (await import(/* @vite-ignore */ resolve(REPO_ROOT, 'frontend', 'scripts', 'generate-cyclonedx-spec.mjs'))) as Generator
}

/**
 * The generated spec file mirrors the backend registry (plan 9.6). Drift
 * fails here: regenerate with `node scripts/generate-cyclonedx-spec.mjs`.
 */
describe.skipIf(!BACKEND_AVAILABLE)('cyclonedx-spec.generated.ts', () => {
  it('equals what the generator writes from the backend modules today', async () => {
    const { generate } = await loadGenerator()
    const regenerated = generate(BACKEND_DIR)
    const committed = readFileSync(GENERATED_PATH, 'utf8')
    expect(committed).toBe(regenerated)
  })

  it('carries every precogly: name the backend registry declares', async () => {
    const { SOURCE_FILES } = await loadGenerator()
    const registrySource = readFileSync(resolve(BACKEND_DIR, SOURCE_FILES.properties), 'utf8')
    const declared = new Set(registrySource.match(/"precogly:[a-z0-9-]+"/g)?.map((match) => match.slice(1, -1)) ?? [])
    expect(declared.size).toBeGreaterThan(30)
    const generatedNames = new Set(PRECOGLY_PROPERTIES.map((entry) => entry.name))
    for (const name of declared) {
      expect(generatedNames.has(name), `${name} missing from the generated file`).toBe(true)
      expect(name.startsWith(PROPERTY_PREFIX)).toBe(true)
    }
  })

  it('mirrors the spec lists the backend re-exports from crossing.py', async () => {
    const { SOURCE_FILES } = await loadGenerator()
    const crossingSource = readFileSync(resolve(BACKEND_DIR, SOURCE_FILES.crossing), 'utf8')
    for (const zoneType of ZONE_TYPES) {
      expect(crossingSource).toContain(`"${zoneType}"`)
    }
  })
})
