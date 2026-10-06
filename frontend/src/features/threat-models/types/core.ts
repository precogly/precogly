import type { Criticality, SystemType } from '@/types/domain'
import type { ScoringMethodKey } from '@/types/risk'

export interface ReferenceImage {
  id: number
  threatModel: number
  image: string
  imageUrl: string
  filename: string
  description: string
  displayOrder: number
  uploadedBy: number | null
  uploadedByEmail: string | null
  createdAt: string
}

export interface Assumption {
  id: string
  description: string
  validity: 'unconfirmed' | 'confirmed' | 'rejected'
  topics: string[]
}

export interface ThreatModel {
  id: string
  name: string
  description: string
  criticality?: Criticality
  frameworks?: Array<{ id: number; name: string }>
  owner?: string
  organizationName?: string
  owningTeam?: number | null
  owningTeamName?: string | null
  canWrite?: boolean
  businessUnitName?: string | null
  systemIds?: string[]
  packIds?: number[]
  connectedPacks?: Array<{
    id: number
    name: string
    slug: string
    version: string
    packType: string
  }>
  referencedModelIds?: string[]
  riskScoringMethod?: ScoringMethodKey
  referenceImages?: ReferenceImage[]
  formatMetadata?: Record<string, unknown>
  assumptions?: Assumption[]
  scopeLocked?: boolean
  scopeLockedAt?: string
  createdAt?: string
  updatedAt?: string
  createdBy?: string
  createdByEmail?: string
  workspaceData?: Record<string, unknown>
  dfds?: Array<{ id: string; name: string; diagramType?: string; isPrimary?: boolean; updatedAt?: string }>
}

export interface CreateThreatModelInput {
  name: string
  owningTeam?: number
}

export interface DashboardRiskStats {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  open: number
  mitigated: number
}

export interface DashboardStats {
  total: number
  risks?: DashboardRiskStats
}

export interface System {
  id: string
  name: string
  type: SystemType
  owner: string
  environment: string
}

export interface CreateSystemInput {
  name: string
  owner?: string
  lifecycleState?: 'development' | 'production' | 'decommissioned'
}
