/**
 * The zone trust level display rule (plan 11.2, F13).
 *
 * A trust level is meaningful on trust and network zones only (plan 11.11).
 * A missing value means "not set": the backend stores null and nothing is
 * shown. The old fallback of 75 is gone.
 */

import { ZONE_TYPES_WITH_TRUST_LEVEL, type ZoneType } from '@/types/domain'
import { getZoneType } from './canvas-defaults'

/** The level a new zone starts at (plan F13). */
export const NEW_ZONE_TRUST_LEVEL = 50

/** Whether the zone type carries a trust level at all. */
export function zoneTypeHasTrustLevel(zoneType: ZoneType): boolean {
  return ZONE_TYPES_WITH_TRUST_LEVEL.includes(zoneType)
}

/** The stored level as a number in 0..100, or null when not set or not a number. */
export function getTrustLevel(data: Record<string, unknown> | null | undefined): number | null {
  const value = data?.trustLevel
  if (typeof value !== 'number' || Number.isNaN(value)) return null
  return Math.max(0, Math.min(100, Math.round(value)))
}

/**
 * The level the canvas and the panel show, or null when nothing should be
 * shown: the level is not set, or the zone type does not carry one.
 */
export function getDisplayedTrustLevel(data: Record<string, unknown> | null | undefined): number | null {
  if (!zoneTypeHasTrustLevel(getZoneType(data))) return null
  return getTrustLevel(data)
}
