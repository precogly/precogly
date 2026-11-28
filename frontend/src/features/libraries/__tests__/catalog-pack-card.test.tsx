import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import { CatalogPackCard } from '../components/CatalogPackCard'
import type { UnifiedPack } from '../components/unified-pack'
import { makePack } from './pack-fixtures'

function renderCard(
  pack: UnifiedPack,
  { isSecurityTeam = true, fullVersionPack = null }: { isSecurityTeam?: boolean; fullVersionPack?: UnifiedPack | null } = {},
): string {
  return renderToStaticMarkup(
    <CatalogPackCard
      pack={pack}
      onImport={() => {}}
      onPreview={() => {}}
      isImporting={false}
      isSecurityTeam={isSecurityTeam}
      fullVersionPack={fullVersionPack}
      onShowFullVersion={() => {}}
    />,
  )
}

describe('CatalogPackCard', () => {
  it('marks a pack imported earlier whose files are gone as source not available', () => {
    const markup = renderCard(
      makePack({ relativePath: '', source: undefined, isInDatabase: true, isImported: true }),
    )
    expect(markup).toContain('data-testid="source-not-available"')
    expect(markup).not.toContain('pack-source-badge')
  })

  it('shows a Demo badge and a Bundled badge on a bundled demo pack', () => {
    const markup = renderCard(
      makePack({ slug: 'demo-aws', relativePath: 'demo-threat-libraries/demo-aws', source: 'bundled' }),
    )
    expect(markup).toContain('data-testid="demo-pack-badge"')
    expect(markup).toContain('Bundled')
    expect(markup).not.toContain('Source not available')
  })

  it('shows a Library repo badge on a catalog pack', () => {
    const markup = renderCard(makePack({ slug: 'aws' }))
    expect(markup).toContain('Library repo')
    expect(markup).not.toContain('demo-pack-badge')
  })

  it('shows both versions and the install button for the security team when the versions differ', () => {
    const outdated = makePack({
      isInDatabase: true,
      isImported: true,
      needsUpdate: true,
      version: '2.1.0',
      databaseVersion: '2.0.0',
    })
    const markup = renderCard(outdated)
    expect(markup).toContain('data-testid="update-available-badge"')
    expect(markup).toContain('Installed 2.0.0, library has 2.1.0')
    expect(markup).toContain('Install 2.1.0')

    expect(renderCard(outdated, { isSecurityTeam: false })).not.toContain('install-version-button')
  })

  it("names the library's version on the button even when it is the lower one", () => {
    const markup = renderCard(
      makePack({ isInDatabase: true, isImported: true, needsUpdate: true, version: '1.0.0', databaseVersion: '2.0.0' }),
    )
    expect(markup).toContain('Installed 2.0.0, library has 1.0.0')
    expect(markup).toContain('Install 1.0.0')
  })

  it('has a Full version link only when the full pack is offered', () => {
    const demo = makePack({ slug: 'demo-aws', source: 'bundled', relativePath: 'demo-threat-libraries/demo-aws' })
    const full = makePack({ slug: 'aws', name: 'AWS' })
    expect(renderCard(demo, { fullVersionPack: full })).toContain('Full version: AWS')
    expect(renderCard(demo)).not.toContain('full-version-link')
  })
})
