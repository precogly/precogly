import { describe, expect, it } from 'vitest'
import {
  REVIEW_FREQUENCY_CUSTOM,
  REVIEW_FREQUENCY_NONE,
  approvalStateLabel,
  dateInputToIso,
  dateInputValue,
  isIso8601Duration,
  reviewFrequencyLabel,
  reviewFrequencySelection,
  sourceDocumentApproval,
} from '../components/workspace/review-utils'

describe('approvalStateLabel', () => {
  it('names the four backend states and treats a missing state as not approved', () => {
    expect(approvalStateLabel('approved')).toBe('Approved')
    expect(approvalStateLabel('changed')).toBe('Changed since approval')
    expect(approvalStateLabel('review_due')).toBe('Review due')
    expect(approvalStateLabel('none')).toBe('Not approved')
    expect(approvalStateLabel(undefined)).toBe('Not approved')
    expect(approvalStateLabel(null)).toBe('Not approved')
  })
})

describe('reviewFrequencySelection', () => {
  it('maps the four presets to themselves', () => {
    expect(reviewFrequencySelection('P1M')).toEqual({ preset: 'P1M', custom: '' })
    expect(reviewFrequencySelection('P3M')).toEqual({ preset: 'P3M', custom: '' })
    expect(reviewFrequencySelection('P6M')).toEqual({ preset: 'P6M', custom: '' })
    expect(reviewFrequencySelection('P1Y')).toEqual({ preset: 'P1Y', custom: '' })
  })

  it('maps an empty value to none and any other duration to custom', () => {
    expect(reviewFrequencySelection('')).toEqual({ preset: REVIEW_FREQUENCY_NONE, custom: '' })
    expect(reviewFrequencySelection(undefined)).toEqual({ preset: REVIEW_FREQUENCY_NONE, custom: '' })
    expect(reviewFrequencySelection('P2W')).toEqual({ preset: REVIEW_FREQUENCY_CUSTOM, custom: 'P2W' })
  })

  it('labels presets by name and custom values verbatim', () => {
    expect(reviewFrequencyLabel('P6M')).toBe('Half-yearly')
    expect(reviewFrequencyLabel('P1Y')).toBe('Yearly')
    expect(reviewFrequencyLabel('P18M')).toBe('P18M')
    expect(reviewFrequencyLabel('')).toBe('Not set')
  })
})

describe('isIso8601Duration', () => {
  it('accepts durations and rejects prose', () => {
    for (const value of ['P1M', 'P3M', 'P1Y', 'P2W', 'P10D', 'P1DT12H', 'PT30M']) {
      expect(isIso8601Duration(value), value).toBe(true)
    }
    for (const value of ['', 'P', 'PT', '3 months', 'monthly', '1M', 'P1M2']) {
      expect(isIso8601Duration(value), value).toBe(false)
    }
  })
})

describe('sourceDocumentApproval', () => {
  it('reads the importer block with party summaries', () => {
    expect(
      sourceDocumentApproval({
        reviewer: { ref: 'party-1', name: 'Lee Tran', email: 'lee@example.com' },
        reviewDate: '2026-09-30T00:00:00Z',
        approver: { ref: 'party-2', name: 'Dana Okafor', email: null },
        approvalDate: '2026-10-02T00:00:00Z',
      })
    ).toEqual({
      reviewerName: 'Lee Tran',
      reviewedAt: '2026-09-30T00:00:00Z',
      approverName: 'Dana Okafor',
      approvedAt: '2026-10-02T00:00:00Z',
    })
  })

  it('falls back to the email, then the ref, and accepts a plain string party', () => {
    expect(sourceDocumentApproval({ approver: { ref: 'party-9', email: 'dana@example.com' } })?.approverName).toBe(
      'dana@example.com'
    )
    expect(sourceDocumentApproval({ approver: { ref: 'party-9' } })?.approverName).toBe('party-9')
    expect(sourceDocumentApproval({ approver: 'Dana' })?.approverName).toBe('Dana')
  })

  it('is null without a block or with an empty one', () => {
    expect(sourceDocumentApproval(null)).toBeNull()
    expect(sourceDocumentApproval(undefined)).toBeNull()
    expect(sourceDocumentApproval({})).toBeNull()
  })
})

describe('date inputs', () => {
  it('round-trips a date through the input and back to an ISO datetime', () => {
    expect(dateInputValue('2026-10-01T00:00:00Z')).toBe('2026-10-01')
    expect(dateInputValue(null)).toBe('')
    expect(dateInputValue('not a date')).toBe('')
    expect(dateInputToIso('2026-10-01')).toBe('2026-10-01T00:00:00Z')
    expect(dateInputToIso('')).toBeNull()
  })
})
