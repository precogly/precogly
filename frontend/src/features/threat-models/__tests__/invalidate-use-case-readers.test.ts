import { describe, expect, it, vi } from 'vitest'
import type { QueryClient } from '@tanstack/react-query'
import { invalidateUseCaseReaders } from '../api/threat-models'

describe('invalidateUseCaseReaders', () => {
  it('refreshes use cases, abuse cases, review state and threats of the model', () => {
    const invalidateQueries = vi.fn()
    invalidateUseCaseReaders({ invalidateQueries } as unknown as QueryClient, '7')
    const keys = invalidateQueries.mock.calls.map(([options]) => options.queryKey)
    expect(keys).toContainEqual(['threat-model-use-cases', '7'])
    expect(keys).toContainEqual(['threat-model-abuse-cases', '7'])
    expect(keys).toContainEqual(['threat-model-threats'])
    expect(keys).toContainEqual(['threats'])
  })
})
