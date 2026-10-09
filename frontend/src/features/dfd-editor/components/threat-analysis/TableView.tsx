/**
 * The table view (plan 11.3): one row per scenario, number first, a Targets
 * column (sorted by the first target), the level, and user sorting on
 * number, targets, status and level. The search box matches the name and
 * `T7`.
 */

import { useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, ArrowUpDown, ExternalLink, Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'
import { RatingBadge } from '@/features/threat-models/components/rating'
import { RATING_LEVEL_RANK } from '@/types/risk'
import { isActiveThreat } from '@/types/triage'
import { TaxonomyBadges } from '@/components/shared/TaxonomyBadges'
import type { AnalysisThreat, ThreatStatus } from '../../types/threat-analysis'
import { deriveThreatStatus, THREAT_STATUS_CONFIG, threatLevel } from '../../types/threat-analysis'
import { NumberBadge } from './NumberBadge'
import { TARGET_TYPE_LABELS } from './analysis-selection'
import { parseThreatSearch, threatMatchesSearch } from './threat-search'

type SortKey = 'number' | 'targets' | 'status' | 'level'
type SortDirection = 'asc' | 'desc'

interface TableViewProps {
  threats: AnalysisThreat[]
  onSelectThreat: (threat: AnalysisThreat) => void
}

interface ThreatRow {
  threat: AnalysisThreat
  targetNames: string[]
  targetsLabel: string
  firstTargetName: string
  status: ThreatStatus
  countermeasureNumbers: string[]
  gaps: number
}

const STATUS_ORDER: Record<ThreatStatus, number> = { exposed: 0, addressable: 1, mitigated: 2 }

function SortableHead({
  label,
  column,
  sortKey,
  sortDirection,
  onToggle,
  className,
}: {
  label: string
  column: SortKey
  sortKey: SortKey
  sortDirection: SortDirection
  onToggle: (column: SortKey) => void
  className?: string
}) {
  const active = sortKey === column
  const Icon = !active ? ArrowUpDown : sortDirection === 'asc' ? ArrowUp : ArrowDown
  return (
    <TableHead className={className}>
      <button
        type="button"
        className={cn('inline-flex items-center gap-1 hover:text-foreground', active && 'text-foreground')}
        onClick={() => onToggle(column)}
        aria-sort={active ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'}
      >
        {label}
        <Icon className="h-3 w-3" />
      </button>
    </TableHead>
  )
}

export function TableView({ threats, onSelectThreat }: TableViewProps) {
  const [sortKey, setSortKey] = useState<SortKey>('number')
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc')
  const [searchText, setSearchText] = useState('')

  const rows = useMemo((): ThreatRow[] => {
    return threats
      .filter((threat) => isActiveThreat(threat.triageStatus))
      .map((threat) => {
        const targetNames = threat.targets.map((target) => target.name || `${TARGET_TYPE_LABELS[target.type]} ${target.id}`)
        return {
          threat,
          targetNames,
          targetsLabel: threat.wholeSystem || targetNames.length === 0 ? 'Whole system' : targetNames.join(', '),
          firstTargetName: threat.wholeSystem ? '' : (targetNames[0] ?? ''),
          status: deriveThreatStatus(threat.countermeasures),
          countermeasureNumbers: threat.countermeasures
            .map((countermeasure) => countermeasure.displayNumber)
            .filter((number): number is string => Boolean(number)),
          gaps: threat.countermeasures.filter((countermeasure) => countermeasure.status === 'gap').length,
        }
      })
  }, [threats])

  const search = useMemo(() => parseThreatSearch(searchText), [searchText])

  const visibleRows = useMemo(() => {
    const filtered = rows.filter((row) =>
      threatMatchesSearch({ number: row.threat.number, threatName: row.threat.threatName, targetNames: row.targetNames }, search)
    )
    const direction = sortDirection === 'asc' ? 1 : -1
    const compare = (left: ThreatRow, right: ThreatRow): number => {
      switch (sortKey) {
        case 'targets':
          return left.firstTargetName.localeCompare(right.firstTargetName) || left.threat.number - right.threat.number
        case 'status':
          return STATUS_ORDER[left.status] - STATUS_ORDER[right.status] || left.threat.number - right.threat.number
        case 'level':
          return (
            RATING_LEVEL_RANK[threatLevel(left.threat)] - RATING_LEVEL_RANK[threatLevel(right.threat)] ||
            left.threat.number - right.threat.number
          )
        default:
          return left.threat.number - right.threat.number
      }
    }
    return [...filtered].sort((left, right) => compare(left, right) * direction)
  }, [rows, search, sortKey, sortDirection])

  const stats = useMemo(
    () => ({
      total: rows.length,
      exposed: rows.filter((row) => row.status === 'exposed').length,
      addressable: rows.filter((row) => row.status === 'addressable').length,
      mitigated: rows.filter((row) => row.status === 'mitigated').length,
    }),
    [rows]
  )

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortDirection((current) => (current === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDirection('asc')
    }
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-6 border-b px-4 py-3">
        <div className="text-sm">
          <span className="font-medium">{stats.total}</span> <span className="text-muted-foreground">threats</span>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-red-500" />
            <span className="text-sm">
              <span className="font-medium">{stats.exposed}</span> <span className="text-muted-foreground">exposed</span>
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-yellow-500" />
            <span className="text-sm">
              <span className="font-medium">{stats.addressable}</span> <span className="text-muted-foreground">in progress</span>
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-green-500" />
            <span className="text-sm">
              <span className="font-medium">{stats.mitigated}</span> <span className="text-muted-foreground">mitigated</span>
            </span>
          </div>
        </div>
        <div className="relative ml-auto w-64">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={searchText}
            onChange={(event) => setSearchText(event.target.value)}
            placeholder="Search, e.g. T7 or a name"
            className="h-8 pl-8 text-sm"
            aria-label="Search threats"
          />
        </div>
      </div>

      <ScrollArea className="flex-1">
        <Table>
          <TableHeader>
            <TableRow>
              <SortableHead label="#" column="number" className="w-[70px]" sortKey={sortKey} sortDirection={sortDirection} onToggle={toggleSort} />
              <SortableHead label="Status" column="status" className="w-[110px]" sortKey={sortKey} sortDirection={sortDirection} onToggle={toggleSort} />
              <SortableHead label="Targets" column="targets" sortKey={sortKey} sortDirection={sortDirection} onToggle={toggleSort} />
              <TableHead>Threat</TableHead>
              <SortableHead label="Level" column="level" className="w-[110px]" sortKey={sortKey} sortDirection={sortDirection} onToggle={toggleSort} />
              <TableHead>Classifications</TableHead>
              <TableHead>Countermeasures</TableHead>
              <TableHead className="text-center">Gaps</TableHead>
              <TableHead className="w-[60px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {visibleRows.map((row) => {
              const statusConfig = THREAT_STATUS_CONFIG[row.status]
              return (
                <TableRow key={row.threat.id} data-threat-number={row.threat.displayNumber}>
                  <TableCell>
                    <NumberBadge number={row.threat.displayNumber} />
                  </TableCell>
                  <TableCell>
                    <span className="inline-flex items-center gap-1.5 text-xs">
                      <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: statusConfig.color }} />
                      <span className="capitalize">{statusConfig.label}</span>
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className={cn('text-sm', row.threat.wholeSystem && 'italic text-muted-foreground')}>{row.targetsLabel}</span>
                    {row.threat.targets.length > 1 && (
                      <Badge variant="outline" className="ml-1.5 px-1 py-0 text-[10px] font-normal">
                        shared
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <span className="font-medium">{row.threat.threatName}</span>
                    {row.threat.libraryMismatch && (
                      <div className="text-[11px] text-amber-700">The library no longer lists this threat here.</div>
                    )}
                  </TableCell>
                  <TableCell>
                    <RatingBadge rating={row.threat.rating} size="sm" />
                  </TableCell>
                  <TableCell>
                    <TaxonomyBadges entries={row.threat.taxonomyEntries ?? []} maxVisible={3} />
                  </TableCell>
                  <TableCell>
                    {row.countermeasureNumbers.length > 0 ? (
                      <span className="inline-flex flex-wrap gap-1">
                        {row.countermeasureNumbers.map((number) => (
                          <NumberBadge key={number} number={number} />
                        ))}
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">none</span>
                    )}
                  </TableCell>
                  <TableCell className="text-center">
                    {row.gaps > 0 ? (
                      <Badge variant="outline" className="bg-red-100 text-red-700">
                        {row.gaps}
                      </Badge>
                    ) : (
                      <span className="text-sm text-muted-foreground">0</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8 w-8 p-0"
                      onClick={() => onSelectThreat(row.threat)}
                      title="View details"
                      aria-label={`Open ${row.threat.displayNumber}`}
                    >
                      <ExternalLink className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              )
            })}

            {visibleRows.length === 0 && (
              <TableRow>
                <TableCell colSpan={9} className="py-8 text-center text-muted-foreground">
                  {rows.length === 0
                    ? 'No threats yet. Add components with a technology, or add threats by hand.'
                    : 'No threat matches the search.'}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </ScrollArea>
    </div>
  )
}
