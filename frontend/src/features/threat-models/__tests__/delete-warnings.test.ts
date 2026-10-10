import { beforeEach, describe, expect, it, vi } from 'vitest'
import { toast } from 'sonner'
import { parseDeleteWarnings, showDeleteWarnings } from '../api/delete-warnings'

vi.mock('sonner', () => ({ toast: { warning: vi.fn() } }))

describe('parseDeleteWarnings', () => {
  it('reads the warnings list of a 200 response', () => {
    expect(
      parseDeleteWarnings({ warnings: ['C3 no longer has a scope and now applies to the whole system'] })
    ).toEqual(['C3 no longer has a scope and now applies to the whole system'])
  })

  it('treats the empty body of a 204 and unexpected shapes as no warnings', () => {
    expect(parseDeleteWarnings({})).toEqual([])
    expect(parseDeleteWarnings(null)).toEqual([])
    expect(parseDeleteWarnings(undefined)).toEqual([])
    expect(parseDeleteWarnings({ warnings: 'oops' })).toEqual([])
    expect(parseDeleteWarnings({ warnings: [1, 'kept'] })).toEqual(['kept'])
  })
})

describe('showDeleteWarnings', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows nothing without warnings', () => {
    showDeleteWarnings([])
    expect(toast.warning).not.toHaveBeenCalled()
  })

  it('shows one warning toast listing every warning', () => {
    showDeleteWarnings(['a', 'b'])
    expect(toast.warning).toHaveBeenCalledTimes(1)
    expect(toast.warning).toHaveBeenCalledWith(expect.any(String), { description: 'a\nb' })
  })
})
