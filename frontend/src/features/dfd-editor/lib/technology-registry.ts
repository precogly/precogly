import type { DiagramNodeType } from '../types'

export interface Technology {
  id: string
  name: string
  category: TechnologyCategory
  description?: string
  icon?: string
  vendor?: 'aws' | 'azure' | 'gcp' | 'generic'
}

export type TechnologyCategory =
  | 'database'
  | 'backend'
  | 'frontend'
  | 'infrastructure'
  | 'messaging'
  | 'cache'
  | 'storage'
  | 'auth'
  | 'monitoring'
  | 'compute'
  | 'networking'
  | 'security'
  | 'other'

// Map diagram node types to relevant technology categories.
// When adding a new TechnologyCategory, add it here too or it won't appear in the combobox.
export const NODE_TYPE_CATEGORIES: Record<DiagramNodeType, TechnologyCategory[]> = {
  datastore: ['database', 'storage', 'cache'],
  process: ['compute', 'backend', 'messaging', 'security', 'networking', 'auth', 'monitoring', 'storage', 'other'],
  humanActor: [], // Human actors typically don't have technologies
  systemActor: [], // System actors (external systems) typically don't have internal technologies
  trustZone: ['networking'], // Will be further filtered by TRUST_ZONE_TECHNOLOGY_IDS
  systemScope: ['infrastructure', 'networking'],
  stickyNote: [],
  table: [], // Annotation, not a component — nothing to assign a technology to
}

// Technology IDs that are appropriate for Trust Zones
// These define network zones/segments, NOT components that sit at boundaries
export const TRUST_ZONE_TECHNOLOGY_IDS: string[] = [
  // AWS VPCs and Subnets
  'aws-vpc',
  'aws-subnet-public',
  'aws-subnet-private',
  'aws-privatelink',
  'aws-transit-gateway',

  // Azure VNets and Subnets
  'azure-vnet',
  'azure-subnet',
  'azure-private-endpoint',
  'azure-virtual-wan',

  // GCP VPCs and Subnets
  'gcp-vpc',
  'gcp-subnet',
  'gcp-private-service-connect',
  'gcp-network-connectivity',

  // Generic Network Boundaries
  'vlan',
  'network-segment',
  'dmz-network',

  // Container/Kubernetes Boundaries
  'k8s-namespace',
  'k8s-network-policy',
  'docker-network',
  'service-mesh',
]

export const TECHNOLOGY_CATEGORIES: Record<TechnologyCategory, { label: string; color: string }> = {
  database: { label: 'Database', color: '#9333ea' },
  backend: { label: 'Backend', color: '#2563eb' },
  frontend: { label: 'Frontend', color: '#16a34a' },
  infrastructure: { label: 'Infrastructure', color: '#ea580c' },
  messaging: { label: 'Messaging', color: '#0891b2' },
  cache: { label: 'Cache', color: '#dc2626' },
  storage: { label: 'Storage', color: '#7c3aed' },
  auth: { label: 'Auth', color: '#ca8a04' },
  monitoring: { label: 'Monitoring', color: '#64748b' },
  compute: { label: 'Compute', color: '#0d9488' },
  networking: { label: 'Networking', color: '#c026d3' },
  security: { label: 'Security Control', color: '#3b82f6' },
  other: { label: 'Other', color: '#475569' },
}
