/**
 * API hooks for fetching component library (technologies) from installed packs.
 */

import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, getAccessToken } from '@/lib/api'
import type { Technology, TechnologyCategory } from '../lib/technology-registry'
import type { DiagramNodeType } from '@/types/domain'

// Backend response type (camelCase from djangorestframework-camel-case middleware)
export interface ComponentLibraryItem {
  id: number
  slug: string
  qualifiedSlug: string | null
  name: string
  category: 'process' | 'datastore' | 'external_human_actor' | 'external_system_actor'
  componentType: string
  provider: string
  iconSvg: string | null
  sourcePack: number | null
  sourcePackName: string | null
  sourcePackSlug: string | null
  sourcePackIconSvg: string | null
}

// Map backend provider to frontend vendor
function mapProviderToVendor(provider: string): Technology['vendor'] {
  const providerLower = provider.toLowerCase()
  if (providerLower === 'aws' || providerLower === 'amazon') return 'aws'
  if (providerLower === 'azure' || providerLower === 'microsoft') return 'azure'
  if (providerLower === 'gcp' || providerLower === 'google') return 'gcp'
  return 'generic'
}

// Map backend component_type to frontend TechnologyCategory
function mapComponentTypeToCategory(componentType: string): TechnologyCategory {
  const type = componentType.toLowerCase()

  // Exact matches first
  const exactMap: Record<string, TechnologyCategory> = {
    database: 'database',
    storage: 'storage',
    cache: 'cache',
    compute: 'compute',
    backend: 'backend',
    frontend: 'frontend',
    messaging: 'messaging',
    networking: 'networking',
    security: 'security',
    auth: 'auth',
    monitoring: 'monitoring',
    infrastructure: 'infrastructure',
  }

  if (exactMap[type]) {
    return exactMap[type]
  }

  // Partial matches for descriptive backend values
  if (type.includes('database')) return 'database'
  if (type.includes('storage')) return 'storage'
  if (type.includes('cache')) return 'cache'
  if (type.includes('queue') || type.includes('messaging') || type.includes('event')) return 'messaging'
  if (type.includes('function') || type.includes('lambda') || type.includes('compute') || type.includes('container')) return 'compute'
  if (type.includes('api') || type.includes('gateway') || type.includes('backend') || type.includes('server')) return 'backend'
  if (type.includes('network') || type.includes('vpc') || type.includes('load balancer') || type.includes('cdn')) return 'networking'
  if (type.includes('auth') || type.includes('identity') || type.includes('iam')) return 'auth'
  if (type.includes('security') || type.includes('firewall') || type.includes('waf')) return 'security'
  if (type.includes('monitor') || type.includes('logging') || type.includes('metric')) return 'monitoring'

  return 'other'
}

// Transform backend item to frontend Technology format
function transformToTechnology(item: ComponentLibraryItem): Technology {
  return {
    id: item.slug || item.qualifiedSlug || String(item.id),
    name: item.name,
    category: mapComponentTypeToCategory(item.componentType),
    vendor: mapProviderToVendor(item.provider),
    description: item.sourcePackName ? `From ${item.sourcePackName}` : undefined,
    icon: item.iconSvg || item.sourcePackIconSvg || undefined,
  }
}

/**
 * Fetch all available technologies from the component library API.
 * Returns technologies from installed packs for the user's organization.
 * Optionally filtered by a threat model's connected packs.
 */
export function useComponentLibrary(threatModelId?: string, options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ['component-library', threatModelId],
    queryFn: async () => {
      const params = threatModelId ? `?threat_model=${threatModelId}` : ''
      const items = await api.get<ComponentLibraryItem[]>(`/component-library/${params}`)
      return items.map(transformToTechnology)
    },
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
    enabled: options?.enabled ?? true,
  })
}

/**
 * Hook that provides technologies with fallback to empty array if no packs installed.
 * Use this in the TechnologyCombobox component.
 */
export function useTechnologies(threatModelId?: string, options?: { enabled?: boolean }) {
  const { data: technologies = [], isLoading, error } = useComponentLibrary(threatModelId, options)

  return {
    technologies,
    isLoading,
    error,
    isEmpty: !isLoading && technologies.length === 0,
  }
}

/**
 * Resolve a technology value (slug or legacy display name) to its display name.
 * Returns the original value as fallback if no match is found (custom entries).
 * Skips the API fetch when no auth token is present (e.g., guest editor).
 */
export function useTechnologyDisplayName(value: string | undefined): string {
  const hasAuth = !!getAccessToken()
  const { technologies } = useTechnologies(undefined, { enabled: hasAuth })

  if (!value) return ''

  const match = technologies.find(
    (t) => t.id === value || t.name.toLowerCase() === value.toLowerCase()
  )
  return match?.name ?? value
}

export function useTechnologyInfo(slug: string | undefined): { displayName: string; iconSvg: string | null } {
  const hasAuth = !!getAccessToken()
  const { technologies } = useTechnologies(undefined, { enabled: hasAuth })

  if (!slug) return { displayName: '', iconSvg: null }

  const match = technologies.find(
    (t) => t.id === slug || t.name.toLowerCase() === slug.toLowerCase()
  )
  return {
    displayName: match?.name ?? slug,
    iconSvg: match?.icon ?? null,
  }
}

const categoryToNodeTypeMap: Record<ComponentLibraryItem['category'], DiagramNodeType> = {
  process: 'process',
  datastore: 'datastore',
  external_human_actor: 'humanActor',
  external_system_actor: 'systemActor',
}

export function categoryToNodeType(category: ComponentLibraryItem['category']): DiagramNodeType {
  return categoryToNodeTypeMap[category]
}

export interface ComponentPanelGroup {
  packName: string
  packSlug: string
  components: ComponentLibraryItem[]
}

export function useGroupedComponentLibrary(threatModelId?: string) {
  const { data: items, isLoading } = useQuery({
    queryKey: ['component-library-grouped', threatModelId],
    queryFn: async () => {
      const params = threatModelId ? `?threat_model=${threatModelId}` : ''
      return api.get<ComponentLibraryItem[]>(`/component-library/${params}`)
    },
    staleTime: 5 * 60 * 1000,
  })

  const groups = useMemo(() => {
    if (!items) return []

    const groupMap = new Map<string, ComponentPanelGroup>()

    for (const item of items) {
      const key = item.sourcePackSlug || '__no_pack__'
      if (!groupMap.has(key)) {
        groupMap.set(key, {
          packName: item.sourcePackName || 'Custom',
          packSlug: key,
          components: [],
        })
      }
      groupMap.get(key)!.components.push(item)
    }

    return Array.from(groupMap.values())
  }, [items])

  return { groups, isLoading }
}
