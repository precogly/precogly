/** Sizes and corner handles shared by the table chrome and TableNode. */

/** Thickness of the hit area for a divider drag. */
export const DIVIDER_HIT = 7
/**
 * Thickness of the row and column grips. Notion and FigJam both span the whole
 * edge rather than offering a small target. The first version here was a 14px
 * strip that appeared only on hover, and it could not be found.
 */
export const GRIP = 18
/** Side of the square corner handles that scale the whole table. */
export const HANDLE = 8
/** Side of the small square action buttons: append a row/column, delete one. */
export const BUTTON = 18
/** Clearance between an action button and whatever edge it sits beside. */
export const GAP = 6

export const CORNERS = [
  { corner: 'nw', cursor: 'cursor-nwse-resize', style: (h: number) => ({ left: -h / 2, top: -h / 2 }) },
  { corner: 'ne', cursor: 'cursor-nesw-resize', style: (h: number) => ({ right: -h / 2, top: -h / 2 }) },
  { corner: 'se', cursor: 'cursor-nwse-resize', style: (h: number) => ({ right: -h / 2, bottom: -h / 2 }) },
  { corner: 'sw', cursor: 'cursor-nesw-resize', style: (h: number) => ({ left: -h / 2, bottom: -h / 2 }) },
] as const
