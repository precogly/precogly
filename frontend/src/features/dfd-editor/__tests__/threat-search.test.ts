import { describe, it, expect } from 'vitest'
import { parseThreatSearch, threatMatchesSearch, isEmptySearch } from '../components/threat-analysis/threat-search'

describe('parseThreatSearch', () => {
  it('reads T7, t7 and a bare 7 as the number 7', () => {
    expect(parseThreatSearch('T7')).toEqual({ numbers: [7], words: [] })
    expect(parseThreatSearch('t7')).toEqual({ numbers: [7], words: [] })
    expect(parseThreatSearch('7')).toEqual({ numbers: [7], words: [] })
  })

  it('keeps the other words lower-cased', () => {
    expect(parseThreatSearch('  Command T7 Injection ')).toEqual({
      numbers: [7],
      words: ['command', 'injection'],
    })
  })

  it('treats T alone and T7a as words', () => {
    expect(parseThreatSearch('T')).toEqual({ numbers: [], words: ['t'] })
    expect(parseThreatSearch('T7a')).toEqual({ numbers: [], words: ['t7a'] })
  })

  it('is empty for blank input', () => {
    expect(isEmptySearch(parseThreatSearch('   '))).toBe(true)
  })
})

describe('threatMatchesSearch', () => {
  const threat = { number: 7, threatName: 'Unauthorized command injection', targetNames: ['PLC', 'Control signals'] }

  it('matches everything on an empty search', () => {
    expect(threatMatchesSearch(threat, parseThreatSearch(''))).toBe(true)
  })

  it('matches by number', () => {
    expect(threatMatchesSearch(threat, parseThreatSearch('T7'))).toBe(true)
    expect(threatMatchesSearch(threat, parseThreatSearch('T8'))).toBe(false)
  })

  it('matches by name words, all of them', () => {
    expect(threatMatchesSearch(threat, parseThreatSearch('command injection'))).toBe(true)
    expect(threatMatchesSearch(threat, parseThreatSearch('command replay'))).toBe(false)
  })

  it('matches a target name', () => {
    expect(threatMatchesSearch(threat, parseThreatSearch('plc'))).toBe(true)
  })

  it('needs both the number and the words to match', () => {
    expect(threatMatchesSearch(threat, parseThreatSearch('T7 command'))).toBe(true)
    expect(threatMatchesSearch(threat, parseThreatSearch('T7 replay'))).toBe(false)
  })
})
