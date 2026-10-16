import { describe, expect, it } from 'vitest'
import { parseExportWarnings } from '../api/threat-models'

describe('parseExportWarnings', () => {
  it('reads the JSON list the export endpoint sends', () => {
    expect(parseExportWarnings('["threats section: dropped relatedRisks \'r-1\'"]')).toEqual([
      "threats section: dropped relatedRisks 'r-1'",
    ])
  })

  it('treats a missing, empty or unreadable header as no warnings', () => {
    expect(parseExportWarnings(null)).toEqual([])
    expect(parseExportWarnings('[]')).toEqual([])
    expect(parseExportWarnings('not json')).toEqual([])
    expect(parseExportWarnings('{"a": 1}')).toEqual([])
    expect(parseExportWarnings('[1, "kept"]')).toEqual(['kept'])
  })
})
