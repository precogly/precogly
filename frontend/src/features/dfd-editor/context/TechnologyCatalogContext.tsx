/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext, useMemo, type ReactNode } from 'react'
import { buildTechnologyCatalog, type TechnologyCatalog, type TechnologyCatalogEntry } from '../lib/technology-catalog'

/**
 * The technologies a diagram's nodes may reference, embedded in the payload
 * that brought the diagram (the magic link share page). Null means no catalog:
 * the node hooks fall back to the component library API, as in the editor.
 * Mirrors DFDNotationContext: the read-only viewer wraps its ReactFlow in it.
 */
const TechnologyCatalogContext = createContext<TechnologyCatalog | null>(null)

export function TechnologyCatalogProvider({
  technologies,
  children,
}: {
  technologies: readonly TechnologyCatalogEntry[] | undefined
  children: ReactNode
}) {
  const catalog = useMemo(() => buildTechnologyCatalog(technologies), [technologies])
  return <TechnologyCatalogContext.Provider value={catalog}>{children}</TechnologyCatalogContext.Provider>
}

export function useTechnologyCatalog(): TechnologyCatalog | null {
  return useContext(TechnologyCatalogContext)
}
