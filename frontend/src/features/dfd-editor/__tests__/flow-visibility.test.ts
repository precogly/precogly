import { describe, it, expect } from 'vitest'
import { FLOW_TYPES } from '@/types/domain'
import {
  FLOW_TYPE_STYLES,
  describeVisibleFlowTypes,
  flowTypeShortLabel,
  isFlowFilterActive,
  isFlowTypeVisible,
  showsFlowTypeChip,
  toggleFlowTypeVisibility,
} from '../lib/flow-visibility'

describe('flow type filter (plan F22)', () => {
  describe('isFlowTypeVisible', () => {
    it('shows every type when no list is stored', () => {
      expect(isFlowTypeVisible('data', undefined)).toBe(true)
      expect(isFlowTypeVisible('signal', null)).toBe(true)
    })

    it('hides a type that is not in the stored list', () => {
      expect(isFlowTypeVisible('data', ['signal', 'control'])).toBe(false)
      expect(isFlowTypeVisible('signal', ['signal', 'control'])).toBe(true)
    })

    it('hides every type when the list is empty', () => {
      expect(isFlowTypeVisible('data', [])).toBe(false)
    })
  })

  describe('isFlowFilterActive', () => {
    it('is off with no list or with every type listed', () => {
      expect(isFlowFilterActive(undefined)).toBe(false)
      expect(isFlowFilterActive(FLOW_TYPES.map((entry) => entry.value))).toBe(false)
    })

    it('is on as soon as one type is missing', () => {
      expect(isFlowFilterActive(['data'])).toBe(true)
      expect(isFlowFilterActive([])).toBe(true)
    })
  })

  describe('toggleFlowTypeVisibility', () => {
    it('unticking data from "all" leaves every other type', () => {
      const next = toggleFlowTypeVisibility(undefined, 'data')
      expect(next).toBeDefined()
      expect(next).not.toContain('data')
      expect(next).toHaveLength(FLOW_TYPES.length - 1)
    })

    it('ticking the last missing type goes back to "all" (nothing stored)', () => {
      const allButData = FLOW_TYPES.map((entry) => entry.value).filter((value) => value !== 'data')
      expect(toggleFlowTypeVisibility(allButData, 'data')).toBeUndefined()
    })

    it('keeps the spec order whatever the click order', () => {
      const next = toggleFlowTypeVisibility(['signal'], 'data')
      expect(next).toEqual(['data', 'signal'])
    })

    it('can hide everything', () => {
      expect(toggleFlowTypeVisibility(['signal'], 'signal')).toEqual([])
    })
  })

  describe('describeVisibleFlowTypes', () => {
    it('says "All flows" with no filter', () => {
      expect(describeVisibleFlowTypes(undefined)).toBe('All flows')
    })

    it('lists the ticked short names, spec order', () => {
      expect(describeVisibleFlowTypes(['control', 'data', 'signal'])).toBe('Data, Control, Signal')
    })

    it('says "No flows" for an empty list', () => {
      expect(describeVisibleFlowTypes([])).toBe('No flows')
    })
  })

  describe('canvas styling by type', () => {
    it('has a style for every flow type', () => {
      for (const entry of FLOW_TYPES) {
        expect(FLOW_TYPE_STYLES[entry.value]).toBeDefined()
      }
    })

    it('draws a data flow solid and every other type with its own pattern or weight', () => {
      expect(FLOW_TYPE_STYLES.data.strokeDasharray).toBeUndefined()
      const patterns = FLOW_TYPES.filter((entry) => entry.value !== 'data').map(
        (entry) => `${FLOW_TYPE_STYLES[entry.value].strokeDasharray ?? 'solid'}/${FLOW_TYPE_STYLES[entry.value].strokeWidth}`
      )
      expect(new Set(patterns).size).toBe(patterns.length)
    })

    it('labels every type except data on the canvas', () => {
      expect(showsFlowTypeChip('data')).toBe(false)
      expect(showsFlowTypeChip('signal')).toBe(true)
      expect(flowTypeShortLabel('signal')).toBe('Signal')
      expect(flowTypeShortLabel('data')).toBe('Data')
    })
  })
})
