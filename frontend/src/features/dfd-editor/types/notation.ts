import {
  TABLE_DEFAULT_COLUMN_WIDTH,
  TABLE_DEFAULT_COLUMNS,
  TABLE_DEFAULT_ROW_HEIGHT,
  TABLE_DEFAULT_ROWS,
} from './diagram'

export type DFDNotationStyle = 'dfd3' | 'yourdon'
export const DEFAULT_NOTATION: DFDNotationStyle = 'dfd3'

// The table is an annotation, so its size is the same under both notations and
// is used only to centre the node under the drop cursor — unlike every other
// entry here it is never applied as `style.width`/`style.height`, because the
// table derives its own size from its column widths and row heights.
const TABLE_SIZE = {
  width: TABLE_DEFAULT_COLUMN_WIDTH * TABLE_DEFAULT_COLUMNS,
  height: TABLE_DEFAULT_ROW_HEIGHT * TABLE_DEFAULT_ROWS,
}

export const NOTATION_NODE_SIZES: Record<DFDNotationStyle, Record<string, { width: number; height: number }>> = {
  dfd3: {
    process: { width: 150, height: 70 },
    datastore: { width: 170, height: 90 },
    humanActor: { width: 100, height: 100 },
    systemActor: { width: 100, height: 90 },
    trustZone: { width: 300, height: 200 },
    systemScope: { width: 300, height: 200 },
    stickyNote: { width: 180, height: 120 },
    table: TABLE_SIZE,
  },
  yourdon: {
    process: { width: 100, height: 100 },
    datastore: { width: 170, height: 50 },
    humanActor: { width: 100, height: 100 },
    systemActor: { width: 100, height: 90 },
    trustZone: { width: 300, height: 200 },
    systemScope: { width: 300, height: 200 },
    stickyNote: { width: 180, height: 120 },
    table: TABLE_SIZE,
  },
}

export const TECHNOLOGY_NODE_SIZES: Record<string, { width: number; height: number }> = {
  process: { width: 90, height: 80 },
  datastore: { width: 90, height: 80 },
  humanActor: { width: 90, height: 80 },
  systemActor: { width: 90, height: 80 },
}
