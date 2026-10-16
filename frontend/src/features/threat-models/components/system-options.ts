/** Option lists for inventory systems (backend/apps/systems/models.py Orgsystem). */

import type { SystemLifecycleState } from '@/features/threat-models/types/core'
import type { Criticality } from '@/types/domain'

export const SYSTEM_CRITICALITIES: Array<{ value: Criticality; label: string }> = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
]

export const SYSTEM_LIFECYCLE_STATES: Array<{ value: SystemLifecycleState; label: string }> = [
  { value: 'development', label: 'Development' },
  { value: 'production', label: 'Production' },
  { value: 'decommissioned', label: 'Decommissioned' },
]
