import type { ReactNode } from 'react'
import { GuestEditorContext, type GuestEditorContextType } from './GuestEditorContext'

export function GuestEditorProvider({
  children,
  value,
}: {
  children: ReactNode
  value: GuestEditorContextType
}) {
  return (
    <GuestEditorContext.Provider value={value}>
      {children}
    </GuestEditorContext.Provider>
  )
}
