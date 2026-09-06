export type DFDNotationStyle = 'dfd3' | 'yourdon'
export const DEFAULT_NOTATION: DFDNotationStyle = 'dfd3'

export const NOTATION_NODE_SIZES: Record<DFDNotationStyle, Record<string, { width: number; height: number }>> = {
  dfd3: {
    process: { width: 150, height: 70 },
    datastore: { width: 170, height: 90 },
    humanActor: { width: 100, height: 100 },
    systemActor: { width: 100, height: 90 },
    trustZone: { width: 300, height: 200 },
    systemScope: { width: 300, height: 200 },
    stickyNote: { width: 180, height: 120 },
  },
  yourdon: {
    process: { width: 100, height: 100 },
    datastore: { width: 170, height: 50 },
    humanActor: { width: 100, height: 100 },
    systemActor: { width: 100, height: 90 },
    trustZone: { width: 300, height: 200 },
    systemScope: { width: 300, height: 200 },
    stickyNote: { width: 180, height: 120 },
  },
}

export const TECHNOLOGY_NODE_SIZES: Record<string, { width: number; height: number }> = {
  process: { width: 90, height: 80 },
  datastore: { width: 90, height: 80 },
  humanActor: { width: 90, height: 80 },
  systemActor: { width: 90, height: 80 },
}
