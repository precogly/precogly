/**
 * Organization and Team types for user management.
 */

import type { TaxonomyEntry } from '@/types/domain'
import type { Rating } from '@/types/risk'

// Role types
export type OrganizationRole = 'security_team' | 'member'
export type TeamRole = 'lead' | 'member' | 'viewer'

// Organization
export interface Organization {
  id: number
  name: string
  domain: string
  plan: 'free' | 'pro' | 'enterprise'
  businessUnitLabel: string
  memberCount: number
  myRole?: OrganizationRole
  createdAt: string
  updatedAt: string
}

// Business Unit (flexible grouping layer)
export interface BusinessUnit {
  id: number
  organization: number
  name: string
  code: string
  description: string
  parent: number | null
  teamCount: number
  createdAt: string
  updatedAt: string
}

// Team
export interface Team {
  id: number
  organization: number
  businessUnit: number | null
  businessUnitName: string | null
  name: string
  code: string
  description: string
  memberCount: number
  isDefault: boolean
  createdAt: string
  updatedAt: string
}

// Team list item (lightweight)
export interface TeamListItem {
  id: number
  name: string
  description?: string
  code: string
  businessUnitName: string | null
  memberCount: number
  isDefault: boolean
  isMember?: boolean
}

// Memberships
export interface OrganizationMembership {
  id: number
  organization: number
  organizationName: string
  user: number
  userEmail: string
  role: OrganizationRole
  joinedAt: string
  createdAt: string
  updatedAt: string
}

export interface TeamMembership {
  id: number
  team: number
  teamName: string
  user: number
  userEmail: string
  userName: string
  role: TeamRole
  joinedAt: string
  createdAt: string
  updatedAt: string
}

// Team Invitation
export interface TeamInvitation {
  id: string
  team: number
  teamName: string
  organizationName: string
  email: string
  role: TeamRole
  token: string
  inviteUrl: string
  invitedBy: number | null
  invitedByEmail: string | null
  status: 'pending' | 'accepted' | 'expired' | 'revoked'
  expiresAt: string
  acceptedAt: string | null
  createdAt: string
  updatedAt: string
}

// Magic Link
export interface MagicLink {
  id: string
  threatModel: number
  threatModelName: string
  token: string
  url: string
  expiresAt: string
  accessedCount: number
  isRevoked: boolean
  createdAt: string
  updatedAt: string
}

// API response types
export interface InviteMemberResponse {
  status: 'added' | 'invited'
  membership?: TeamMembership
  invitation?: TeamInvitation
}

export interface JoinTeamResponse {
  joined: boolean
  membership: TeamMembership
}

export interface AcceptInvitationResponse {
  status: 'accepted'
  membership: TeamMembership
}

export interface InvitationDetailsResponse {
  invitation: TeamInvitation
  requiresSignup: boolean
}

export interface ThreatModelStats {
  components: {
    total: number
    processes: number
    datastores: number
    humanActors: number
    systemActors: number
    boundaries: number
  }
  threats: {
    total: number
    exposed: number
    mitigated: number
  }
  countermeasures: {
    total: number
    verified: number
    gaps: number
  }
  // Keys as organizations/views.py MagicLinkAccessView computes them (camelCased).
  progress: {
    assetsDefined: boolean
    componentsIdentified: boolean
    boundariesIdentified: boolean
    flowsDefined: boolean
    ownersAssigned: boolean
    threatsLinkedComponents: boolean
    threatsLinkedFlows: boolean
    countermeasuresAssigned: boolean
  }
}

// Threat Analysis types for magic link sharing
export interface ComplianceStandard {
  id: number
  frameworkName: string
  frameworkSlug: string
  sectionCode: string
  requirementDescription: string
  sufficiency: 'full' | 'partial' | 'supplemental'
}

/** A target in the shared payload (analysis_service.SHARED_TARGET_KEYS). */
export interface SharedTarget {
  type: 'component' | 'flow' | 'zone' | 'boundary'
  id: number
  name: string | null
  blueprintId: number
  nodeId: string | null
  edgeId: string | null
  dfdId: string | null
  dfdName: string | null
}

// The shared (magic-link) form of the threat analysis payload. Same shape as
// the signed-in payload from /threat-models/{id}/threats/, restricted to the
// backend's allow-list (analysis_service.SHARED_THREAT_KEYS and
// SHARED_COUNTERMEASURE_KEYS). The shared view shows nothing it did not show
// before unless a key is added to that list on purpose (M6).
export interface SharedCountermeasure {
  id: number
  number: number
  displayNumber: string
  targets: SharedTarget[]
  countermeasureLibraryId: number | null
  countermeasureName: string | null
  countermeasureDescription: string | null
  controlFunctions: string[] | null
  controlNature: string | null
  status: 'gap' | 'planned' | 'in_progress' | 'implemented' | 'verified' | 'waived' | 'platform' | 'decommissioned'
  priority: string
  evidenceUrl: string
  assignedOwnerEmail: string | null
  verifiedByEmail: string | null
  standardMappings: ComplianceStandard[]
}

export interface SharedThreat {
  id: number
  number: number
  displayNumber: string
  wholeSystem: boolean
  targets: SharedTarget[]
  threatLibraryId: number | null
  threatName: string | null
  threatDescription: string | null
  taxonomyEntries?: TaxonomyEntry[]
  rating: Rating | null
  status: 'exposed' | 'addressable' | 'mitigated'
  triageStatus: string
  countermeasures: SharedCountermeasure[]
}

export interface ThreatAnalysisData {
  threatModelId: string
  threats: SharedThreat[]
  totalCount: number
  nodeComponentMap: Record<string, { componentId: number; dfdId: string | null; dfdName: string | null }>
  edgeFlowMap: Record<string, { flowId: number; dfdId: string | null; dfdName: string | null }>
}

export interface MagicLinkAccessResponse {
  threatModel: {
    id: number
    name: string
    description: string
    version: string
    status: string
    criticality: string
    workspaceData?: {
      systemContext?: {
        description?: string
        assets?: Array<{ name: string; description?: string }>
        outOfScopeItems?: string[]
      }
    }
    referenceImages?: Array<{
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
    }>
    dfds?: Array<{
      id: number
      name: string
      isPrimary?: boolean
      canvasData?: {
        nodes?: unknown[]
        edges?: unknown[]
      }
    }>
  }
  stats: ThreatModelStats
  threatAnalysis: ThreatAnalysisData
  readOnly: boolean
  expiresAt: string
  isAuthenticated: boolean
  savedToAccount: boolean
}

// Shared with Me - threat models shared via magic link
export interface SharedWithMe {
  id: number
  threatModelId: number
  threatModelName: string
  threatModelDescription: string
  organizationName: string
  sharedBy: {
    email: string
    name: string
  } | null
  shareUrl: string | null
  firstAccessedAt: string
  lastAccessedAt: string
  accessCount: number
}
