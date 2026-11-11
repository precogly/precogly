import { afterEach, describe, it, expect, vi } from 'vitest'
import type React from 'react'
import { referenceLinkProps } from '../taxonomy-reference-link'

const cweUrl = 'https://cwe.mitre.org/data/definitions/494.html'

function fakeEvent(key?: string) {
  return { key, stopPropagation: vi.fn(), preventDefault: vi.fn() }
}

describe('referenceLinkProps', () => {
  const openWindow = vi.fn()

  afterEach(() => {
    vi.unstubAllGlobals()
    openWindow.mockReset()
  })

  it('gives nothing for an entry without a reference', () => {
    expect(referenceLinkProps({})).toEqual({})
  })

  it('makes a focusable link for an entry with a reference', () => {
    const linkProps = referenceLinkProps({ referenceUrl: cweUrl })
    expect(linkProps.role).toBe('link')
    expect(linkProps.tabIndex).toBe(0)
    expect(linkProps.onClick).toBeTypeOf('function')
  })

  it('opens the reference in a new tab on click, without bubbling', () => {
    vi.stubGlobal('window', { open: openWindow })
    const event = fakeEvent()
    referenceLinkProps({ referenceUrl: cweUrl }).onClick!(event as unknown as React.SyntheticEvent)
    expect(event.stopPropagation).toHaveBeenCalled()
    expect(event.preventDefault).toHaveBeenCalled()
    expect(openWindow).toHaveBeenCalledWith(cweUrl, '_blank', 'noopener,noreferrer')
  })

  it('opens on Enter and Space, and ignores other keys', () => {
    vi.stubGlobal('window', { open: openWindow })
    const { onKeyDown } = referenceLinkProps({ referenceUrl: cweUrl })
    onKeyDown!(fakeEvent('Enter') as unknown as React.KeyboardEvent)
    onKeyDown!(fakeEvent(' ') as unknown as React.KeyboardEvent)
    onKeyDown!(fakeEvent('Tab') as unknown as React.KeyboardEvent)
    expect(openWindow).toHaveBeenCalledTimes(2)
  })
})
