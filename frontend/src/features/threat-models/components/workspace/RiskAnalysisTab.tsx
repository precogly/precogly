/**
 * The Risk Register tab (plan 11.4): a paginated table or a board grouped by
 * the six lifecycle statuses, a detail panel for the selected risk, bulk
 * status and owner updates, and the model's scoring method.
 *
 * The pieces live under `./risk/`: the detail panel (statement, exposure,
 * domains, objectives, threats, ratings, responses), the add dialog, the
 * threat picker and the pure helpers.
 */

import { useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import {
  CheckSquare,
  ChevronRight,
  LayoutGrid,
  Loader2,
  Plus,
  RefreshCw,
  Search,
  Square,
  Table2,
  Trash2,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationNext,
  PaginationPrevious,
} from '@/components/ui/pagination'
import {
  DEFAULT_RISK_PAGE_SIZE,
  RISK_PAGE_SIZES,
  useBulkUpdateRisks,
  useDeleteRisk,
  useRecalculateRisk,
  useRisks,
  useScoringMethods,
  useUpdateRisk,
  type RiskListFilters,
} from '@/features/threat-models/api/risks'
import { RatingBadge } from '@/features/threat-models/components/rating'
import type { ComponentThreat } from '@/features/dfd-editor/types/threat-analysis'
import {
  RATING_LEVELS,
  RISK_STATUSES,
  type Risk,
  type RiskStatus,
  type ScoringMethod,
  type ScoringMethodKey,
} from '@/types/risk'
import { useWorkspace } from '@/contexts/WorkspaceContext'
import { useOrganizationMembers } from '@/features/organization/api/organizations'
import { AddRiskDialog } from './risk/AddRiskDialog'
import { RiskDetailPanel, RiskExposureBadge, RiskStatusBadge } from './risk/RiskDetailPanel'
import type { OwnerOption } from './risk/RiskResponsesTable'
import {
  METHODOLOGY_GUARD_MESSAGE,
  RISK_BOARD_COLUMNS,
  apiErrorMessage,
  groupRisksByStatus,
} from './risk/risk-utils'

interface RiskAnalysisTabProps {
  threatModelId: string
  /** The model's threats from the analysis payload; the threat picker and the countermeasure labels read them. */
  componentThreats: ComponentThreat[]
  riskScoringMethod: ScoringMethodKey
  onScoringMethodChange: (method: ScoringMethodKey) => void
}

type ViewMode = 'table' | 'kanban'

const ANY_VALUE = '_any'

function scaleFor(risk: Risk, field: 'inherent' | 'residual', scoringMethods: ScoringMethod[] | undefined) {
  const rating = risk[field]
  if (!rating) return null
  return scoringMethods?.find((method) => method.key === rating.methodology)?.scoreScale ?? null
}

// ─── Kanban board ─────────────────────────────────────────────────────────────

function KanbanCard({
  risk,
  isSelected,
  onSelect,
  onDelete,
}: {
  risk: Risk
  isSelected: boolean
  onSelect: () => void
  onDelete: () => void
}) {
  return (
    <div
      className={`bg-white border rounded-lg p-3 shadow-sm cursor-pointer hover:shadow-md transition-shadow ${isSelected ? 'ring-2 ring-primary' : ''}`}
      onClick={onSelect}
      data-testid="risk-card"
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <span className="text-sm font-medium leading-tight">{risk.name}</span>
        <Button
          variant="ghost"
          size="sm"
          className="h-5 w-5 p-0 shrink-0"
          aria-label={`Delete ${risk.name}`}
          onClick={(event) => {
            event.stopPropagation()
            onDelete()
          }}
        >
          <Trash2 className="h-3 w-3 text-muted-foreground" />
        </Button>
      </div>
      <div className="flex items-center gap-1.5 flex-wrap">
        <RatingBadge rating={risk.inherent} size="sm" />
        <RiskExposureBadge exposure={risk.exposure} />
      </div>
      {risk.ownerEmail && <p className="text-xs text-muted-foreground mt-1 truncate">{risk.ownerEmail}</p>}
    </div>
  )
}

function KanbanBoard({
  risks,
  selectedRiskId,
  onSelectRisk,
  onDeleteRisk,
  threatModelId,
}: {
  risks: Risk[]
  selectedRiskId: number | null
  onSelectRisk: (id: number) => void
  onDeleteRisk: (id: number) => void
  threatModelId: string
}) {
  const updateRisk = useUpdateRisk(threatModelId)
  const grouped = useMemo(() => groupRisksByStatus(risks), [risks])

  const handleDrop = (event: React.DragEvent, targetStatus: RiskStatus) => {
    event.preventDefault()
    const riskId = Number(event.dataTransfer.getData('riskId'))
    const risk = risks.find((entry) => entry.id === riskId)
    if (!risk || risk.status === targetStatus) return
    updateRisk.mutate(
      { riskId, data: { status: targetStatus } },
      { onError: (error) => toast.error(apiErrorMessage(error, 'Failed to move the risk.')) }
    )
  }

  return (
    <div className="grid grid-cols-6 items-start gap-4" data-testid="risk-board">
      {RISK_BOARD_COLUMNS.map((column) => {
        const columnRisks = grouped[column.status]
        return (
          <div
            key={column.status}
            className={`rounded-lg border-2 ${column.className} p-3`}
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => handleDrop(event, column.status)}
            data-testid={`risk-column-${column.status}`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm font-semibold">{column.label}</span>
              <Badge variant="secondary" className="text-xs">
                {columnRisks.length}
              </Badge>
            </div>
            <div className="space-y-2">
              {columnRisks.map((risk) => (
                <div
                  key={risk.id}
                  draggable
                  onDragStart={(event) => event.dataTransfer.setData('riskId', String(risk.id))}
                >
                  <KanbanCard
                    risk={risk}
                    isSelected={selectedRiskId === risk.id}
                    onSelect={() => onSelectRisk(risk.id)}
                    onDelete={() => onDeleteRisk(risk.id)}
                  />
                </div>
              ))}
              {columnRisks.length === 0 && (
                <div className="border border-dashed rounded-md py-4 text-xs text-muted-foreground text-center">
                  Drop here
                </div>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Bulk action bar ──────────────────────────────────────────────────────────

type BulkField = 'status' | 'owner'

function BulkActionBar({
  selectedIds,
  threatModelId,
  owners,
  onClear,
  isPaginated,
}: {
  selectedIds: number[]
  threatModelId: string
  owners: OwnerOption[]
  onClear: () => void
  /** Select-all ticks the loaded rows, which is every row only when the register
      fits on one page. Past that the label has to say so. */
  isPaginated: boolean
}) {
  const bulkUpdate = useBulkUpdateRisks(threatModelId)
  const [field, setField] = useState<BulkField>('status')
  const [bulkStatus, setBulkStatus] = useState<RiskStatus | ''>('')
  const [bulkOwner, setBulkOwner] = useState<string>('')

  const canApply = field === 'status' ? Boolean(bulkStatus) : Boolean(bulkOwner)

  const handleApply = () => {
    if (!canApply) return
    const data =
      field === 'status'
        ? { riskIds: selectedIds, status: bulkStatus as RiskStatus }
        : { riskIds: selectedIds, owner: bulkOwner === '_none' ? null : Number(bulkOwner) }
    bulkUpdate.mutate(data, {
      onSuccess: onClear,
      onError: (error) => toast.error(apiErrorMessage(error, 'Bulk update failed.')),
    })
  }

  return (
    <div className="flex items-center gap-3 p-3 bg-muted/60 border rounded-lg flex-wrap" data-testid="risk-bulk-bar">
      <span className="text-sm font-medium">
        {selectedIds.length} selected{isPaginated && ' on this page'}
      </span>
      <Select value={field} onValueChange={(value) => setField(value as BulkField)}>
        <SelectTrigger className="h-8 w-[120px]" aria-label="Bulk field">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="status">Set status</SelectItem>
          <SelectItem value="owner">Set owner</SelectItem>
        </SelectContent>
      </Select>
      {field === 'status' ? (
        <Select value={bulkStatus} onValueChange={(value) => setBulkStatus(value as RiskStatus)}>
          <SelectTrigger className="h-8 w-[150px]" aria-label="Bulk status">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            {RISK_STATUSES.map((entry) => (
              <SelectItem key={entry.value} value={entry.value}>
                {entry.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      ) : (
        <Select value={bulkOwner} onValueChange={setBulkOwner}>
          <SelectTrigger className="h-8 w-[200px]" aria-label="Bulk owner">
            <SelectValue placeholder="Owner" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_none">No owner</SelectItem>
            {owners.map((owner) => (
              <SelectItem key={owner.userId} value={String(owner.userId)}>
                {owner.email}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      <Button size="sm" onClick={handleApply} disabled={!canApply || bulkUpdate.isPending}>
        {bulkUpdate.isPending ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : null}
        Apply
      </Button>
      <Button size="sm" variant="ghost" onClick={onClear}>
        Clear
      </Button>
    </div>
  )
}

// ─── Table view ───────────────────────────────────────────────────────────────

function TableView({
  risks,
  selectedRiskId,
  selectedIds,
  scoringMethods,
  onSelectRisk,
  onToggleSelect,
  onToggleSelectAll,
  onDeleteRisk,
  onRecalculateRisk,
  recalculatingRiskId,
}: {
  risks: Risk[]
  selectedRiskId: number | null
  selectedIds: number[]
  scoringMethods: ScoringMethod[] | undefined
  onSelectRisk: (id: number) => void
  onToggleSelect: (id: number) => void
  onToggleSelectAll: () => void
  onDeleteRisk: (id: number) => void
  onRecalculateRisk: (id: number) => void
  recalculatingRiskId: number | null
}) {
  const allSelected = risks.length > 0 && selectedIds.length === risks.length

  return (
    <div className="border rounded-lg" data-testid="risk-table">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[40px]">
              <button onClick={onToggleSelectAll} className="flex items-center" aria-label="Select all on this page">
                {allSelected ? (
                  <CheckSquare className="h-4 w-4 text-primary" />
                ) : (
                  <Square className="h-4 w-4 text-muted-foreground" />
                )}
              </button>
            </TableHead>
            <TableHead>Name</TableHead>
            <TableHead className="w-[130px]">Inherent</TableHead>
            <TableHead className="w-[130px]">Residual</TableHead>
            <TableHead className="w-[110px]">Status</TableHead>
            <TableHead className="w-[110px]">Exposure</TableHead>
            <TableHead className="w-[140px]">Owner</TableHead>
            <TableHead className="w-[70px]">Threats</TableHead>
            <TableHead className="w-[100px]">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {risks.map((risk) => (
            <TableRow
              key={risk.id}
              className={`cursor-pointer ${selectedRiskId === risk.id ? 'bg-muted/50' : ''}`}
              onClick={() => onSelectRisk(risk.id)}
              data-testid="risk-row"
            >
              <TableCell onClick={(event) => event.stopPropagation()}>
                <Checkbox
                  checked={selectedIds.includes(risk.id)}
                  onCheckedChange={() => onToggleSelect(risk.id)}
                  aria-label={`Select ${risk.name}`}
                />
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <span className="font-medium">{risk.name}</span>
                  <ChevronRight className="h-3 w-3 text-muted-foreground" />
                </div>
              </TableCell>
              <TableCell>
                <RatingBadge rating={risk.inherent} scoreScale={scaleFor(risk, 'inherent', scoringMethods)} />
              </TableCell>
              <TableCell>
                <RatingBadge rating={risk.residual} scoreScale={scaleFor(risk, 'residual', scoringMethods)} />
              </TableCell>
              <TableCell>
                <RiskStatusBadge status={risk.status} />
              </TableCell>
              <TableCell>
                <RiskExposureBadge exposure={risk.exposure} />
              </TableCell>
              <TableCell className="text-sm text-muted-foreground truncate">{risk.ownerEmail ?? '-'}</TableCell>
              <TableCell className="text-center text-sm text-muted-foreground">{risk.threatCount ?? 0}</TableCell>
              <TableCell className="whitespace-nowrap">
                <Button
                  variant="ghost"
                  size="sm"
                  title="Recalculate residual risk"
                  aria-label={`Recalculate residual risk for ${risk.name}`}
                  disabled={recalculatingRiskId === risk.id}
                  onClick={(event) => {
                    event.stopPropagation()
                    onRecalculateRisk(risk.id)
                  }}
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 text-muted-foreground ${recalculatingRiskId === risk.id ? 'animate-spin' : ''}`}
                  />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={`Delete ${risk.name}`}
                  onClick={(event) => {
                    event.stopPropagation()
                    onDeleteRisk(risk.id)
                  }}
                >
                  <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

// ─── Pagination ───────────────────────────────────────────────────────────────

/**
 * Props that make a `PaginationPrevious`/`PaginationNext` unusable at a boundary.
 *
 * Those render an `<a>`, which has no `disabled`: the component is built for
 * href-based paging, while this register drives state from `onClick`. Kept here
 * rather than patched into `components/ui/pagination.tsx` so that file stays a
 * verbatim copy of upstream.
 */
function boundaryProps(atBoundary: boolean) {
  return atBoundary
    ? {
        'aria-disabled': true,
        tabIndex: -1,
        className: 'pointer-events-none opacity-50',
      }
    : {}
}

function RegisterPagination({
  page,
  pageCount,
  pageSize,
  onPageChange,
  onPageSizeChange,
}: {
  page: number
  pageCount: number
  pageSize: number
  onPageChange: (page: number) => void
  onPageSizeChange: (pageSize: number) => void
}) {
  return (
    <div className="flex items-center justify-between gap-3 flex-wrap">
      <div className="flex items-center gap-2">
        <Label className="text-sm text-muted-foreground whitespace-nowrap">Per page:</Label>
        <Select value={String(pageSize)} onValueChange={(value) => onPageSizeChange(Number(value))}>
          <SelectTrigger className="h-8 w-[80px]" aria-label="Rows per page">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {RISK_PAGE_SIZES.map((size) => (
              <SelectItem key={size} value={String(size)}>
                {size}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <Pagination className="mx-0 w-auto justify-end">
        <PaginationContent>
          <PaginationItem>
            <PaginationPrevious
              href="#"
              onClick={(event) => {
                event.preventDefault()
                onPageChange(page - 1)
              }}
              {...boundaryProps(page <= 1)}
            />
          </PaginationItem>
          <PaginationItem>
            <span className="px-3 text-sm text-muted-foreground tabular-nums">
              Page {page} of {pageCount}
            </span>
          </PaginationItem>
          <PaginationItem>
            <PaginationNext
              href="#"
              onClick={(event) => {
                event.preventDefault()
                onPageChange(page + 1)
              }}
              {...boundaryProps(page >= pageCount)}
            />
          </PaginationItem>
        </PaginationContent>
      </Pagination>
    </div>
  )
}

// ─── Filters ──────────────────────────────────────────────────────────────────

function RegisterFilters({
  filters,
  searchDraft,
  onSearchDraftChange,
  onFiltersChange,
}: {
  filters: RiskListFilters
  searchDraft: string
  onSearchDraftChange: (value: string) => void
  onFiltersChange: (next: RiskListFilters) => void
}) {
  return (
    <div className="flex items-center gap-2 flex-wrap" data-testid="risk-filters">
      <div className="relative">
        <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
        <Input
          value={searchDraft}
          onChange={(event) => onSearchDraftChange(event.target.value)}
          placeholder="Search risks"
          className="h-8 pl-7 text-sm w-[220px]"
          aria-label="Search risks"
        />
      </div>
      <Select
        value={filters.status ?? ANY_VALUE}
        onValueChange={(value) => onFiltersChange({ ...filters, status: value === ANY_VALUE ? undefined : (value as RiskStatus) })}
      >
        <SelectTrigger className="h-8 w-[150px]" aria-label="Filter by status">
          <SelectValue placeholder="Any status" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ANY_VALUE}>Any status</SelectItem>
          {RISK_STATUSES.map((entry) => (
            <SelectItem key={entry.value} value={entry.value}>
              {entry.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select
        value={filters.inherentLevel ?? ANY_VALUE}
        onValueChange={(value) => onFiltersChange({ ...filters, inherentLevel: value === ANY_VALUE ? undefined : value })}
      >
        <SelectTrigger className="h-8 w-[160px]" aria-label="Filter by inherent level">
          <SelectValue placeholder="Any inherent level" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ANY_VALUE}>Any inherent level</SelectItem>
          {RATING_LEVELS.map((entry) => (
            <SelectItem key={entry.value} value={entry.value}>
              {entry.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export function RiskAnalysisTab({
  threatModelId,
  componentThreats,
  riskScoringMethod,
  onScoringMethodChange,
}: RiskAnalysisTabProps) {
  const [viewMode, setViewMode] = useState<ViewMode>('table')
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [selectedRiskId, setSelectedRiskId] = useState<number | null>(null)
  const [deleteRiskId, setDeleteRiskId] = useState<number | null>(null)
  const [selectedIds, setSelectedIds] = useState<number[]>([])
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState<number>(DEFAULT_RISK_PAGE_SIZE)
  const [filters, setFilters] = useState<RiskListFilters>({})
  const [searchDraft, setSearchDraft] = useState('')

  // The search box writes the filter after a short pause, so each keystroke
  // does not fetch a page.
  useEffect(() => {
    const handle = window.setTimeout(() => {
      setFilters((previous) => {
        const nextSearch = searchDraft.trim() || undefined
        return previous.search === nextSearch ? previous : { ...previous, search: nextSearch }
      })
    }, 300)
    return () => window.clearTimeout(handle)
  }, [searchDraft])

  const { data: riskPage, isLoading } = useRisks(threatModelId, { page, pageSize, ...filters })
  const { data: scoringMethods } = useScoringMethods()
  const deleteRisk = useDeleteRisk(threatModelId)
  const recalculateRisk = useRecalculateRisk(threatModelId)
  const { currentOrganization } = useWorkspace()
  const { data: organizationMembers = [] } = useOrganizationMembers(currentOrganization?.id ?? 0)
  const owners: OwnerOption[] = useMemo(
    () => organizationMembers.map((member) => ({ userId: member.user, email: member.userEmail })),
    [organizationMembers]
  )

  // `risks` is one page; `totalRisks` is the register (as filtered). Everything
  // the user can act on, select, bulk-update, drag between board columns, is
  // scoped to the page, because that is all the client has.
  const risks = riskPage?.results
  const totalRisks = riskPage?.count ?? 0
  const pageCount = Math.max(1, Math.ceil(totalRisks / pageSize))
  const firstRowNumber = (page - 1) * pageSize + 1
  const lastRowNumber = firstRowNumber + (risks?.length ?? 0) - 1
  const hasFilters = Boolean(filters.search || filters.status || filters.inherentLevel)

  const selectedRisk = risks?.find((risk) => risk.id === selectedRiskId)
  const activeScoringMethod = scoringMethods?.find((method) => method.key === riskScoringMethod)

  // Selection can only refer to rows that are loaded, so leaving the page drops
  // it rather than silently carrying ids the user can no longer see.
  const goToPage = (next: number) => {
    setPage(next)
    setSelectedIds([])
    setSelectedRiskId(null)
  }

  const changePageSize = (next: number) => {
    setPageSize(next)
    goToPage(1)
  }

  const changeFilters = (next: RiskListFilters) => {
    setFilters(next)
    goToPage(1)
  }

  // The backend refuses a method change once the model has risks (the
  // methodology guard, #31 comment 2.1). The parent's mutation does not
  // surface that error, so the guard is applied here before the call, on the
  // register count the tab has (a filtered empty page lets the call through
  // and the backend still refuses it).
  const handleScoringMethodChange = (method: ScoringMethodKey) => {
    if (method === riskScoringMethod) return
    if (totalRisks > 0) {
      toast.error(METHODOLOGY_GUARD_MESSAGE)
      return
    }
    onScoringMethodChange(method)
  }

  const handleDelete = () => {
    if (deleteRiskId === null) return
    deleteRisk.mutate(deleteRiskId, {
      onSuccess: () => {
        setDeleteRiskId(null)
        if (selectedRiskId === deleteRiskId) setSelectedRiskId(null)
        setSelectedIds((previous) => previous.filter((id) => id !== deleteRiskId))
        // Deleting a page's last row leaves `page` past the end. DRF answers an
        // out-of-range page with a 404 rather than an empty one, so step back
        // before the refetch asks for it.
        if (page > 1 && risks?.length === 1) goToPage(page - 1)
      },
      onError: (error) => toast.error(apiErrorMessage(error, 'Failed to delete the risk.')),
    })
  }

  const handleToggleSelect = (id: number) => {
    setSelectedIds((previous) => (previous.includes(id) ? previous.filter((entry) => entry !== id) : [...previous, id]))
  }

  const handleToggleSelectAll = () => {
    if (!risks) return
    setSelectedIds(selectedIds.length === risks.length ? [] : risks.map((risk) => risk.id))
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  const detailPanel = selectedRisk ? (
    <RiskDetailPanel
      threatModelId={threatModelId}
      risk={selectedRisk}
      componentThreats={componentThreats}
      owners={owners}
      scoringMethod={activeScoringMethod}
      scoringMethods={scoringMethods}
      onClose={() => setSelectedRiskId(null)}
    />
  ) : null

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold">Risk Register</h2>
          <p className="text-sm text-muted-foreground">
            {totalRisks} risk{totalRisks !== 1 ? 's' : ''}
            {hasFilters && ' matching'}
            {pageCount > 1 && `, showing ${firstRowNumber} to ${lastRowNumber}`}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Scoring method */}
          <div className="flex items-center gap-2">
            <Label className="text-sm text-muted-foreground whitespace-nowrap">Scoring:</Label>
            <Select value={riskScoringMethod} onValueChange={(value) => handleScoringMethodChange(value as ScoringMethodKey)}>
              <SelectTrigger className="w-[220px]" aria-label="Scoring method">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(scoringMethods ?? []).map((method) => (
                  <SelectItem key={method.key} value={method.key} disabled={!method.available}>
                    {method.label}
                    {!method.available && ' (coming soon)'}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {/* View toggle */}
          <div className="flex border rounded-md overflow-hidden">
            <Button
              variant={viewMode === 'table' ? 'default' : 'ghost'}
              size="sm"
              className="rounded-none"
              aria-label="Table view"
              aria-pressed={viewMode === 'table'}
              onClick={() => setViewMode('table')}
            >
              <Table2 className="h-4 w-4" />
            </Button>
            <Button
              variant={viewMode === 'kanban' ? 'default' : 'ghost'}
              size="sm"
              className="rounded-none"
              aria-label="Board view"
              aria-pressed={viewMode === 'kanban'}
              onClick={() => setViewMode('kanban')}
            >
              <LayoutGrid className="h-4 w-4" />
            </Button>
          </div>
          <Button onClick={() => setAddDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Add Risk
          </Button>
        </div>
      </div>

      <RegisterFilters
        filters={filters}
        searchDraft={searchDraft}
        onSearchDraftChange={setSearchDraft}
        onFiltersChange={changeFilters}
      />

      {/* Bulk action bar */}
      {selectedIds.length > 0 && viewMode === 'table' && (
        <BulkActionBar
          selectedIds={selectedIds}
          threatModelId={threatModelId}
          owners={owners}
          onClear={() => setSelectedIds([])}
          isPaginated={pageCount > 1}
        />
      )}

      {/* An empty column does not mean no risks carry that status; they may
          be on another page. Nothing on the board itself shows that. */}
      {viewMode === 'kanban' && pageCount > 1 && (
        <p className="text-sm text-muted-foreground">
          Board shows risks {firstRowNumber} to {lastRowNumber} of {totalRisks}. Column counts are for this
          page; raise the page size to see more of the register at once.
        </p>
      )}

      {/* Empty state */}
      {!risks || risks.length === 0 ? (
        <Card className="p-12 text-center">
          <p className="text-muted-foreground mb-4">
            {hasFilters ? 'No risks match these filters.' : 'No risks defined yet. Add a risk manually to get started.'}
          </p>
          <div className="flex items-center justify-center gap-3">
            {hasFilters ? (
              <Button
                variant="outline"
                onClick={() => {
                  setSearchDraft('')
                  changeFilters({})
                }}
              >
                Clear filters
              </Button>
            ) : (
              <Button onClick={() => setAddDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                Add Risk
              </Button>
            )}
          </div>
        </Card>
      ) : (
        <>
          <div className="flex gap-6">
            {/* Main content */}
            <div className={`flex-1 min-w-0 ${selectedRisk && viewMode === 'table' ? 'max-w-[55%]' : ''}`}>
              {viewMode === 'table' ? (
                <TableView
                  risks={risks}
                  selectedRiskId={selectedRiskId}
                  selectedIds={selectedIds}
                  scoringMethods={scoringMethods}
                  onSelectRisk={setSelectedRiskId}
                  onToggleSelect={handleToggleSelect}
                  onToggleSelectAll={handleToggleSelectAll}
                  onDeleteRisk={setDeleteRiskId}
                  onRecalculateRisk={(riskId) =>
                    recalculateRisk.mutate(riskId, {
                      onError: (error) => toast.error(apiErrorMessage(error, 'Failed to recalculate the residual rating.')),
                    })
                  }
                  recalculatingRiskId={recalculateRisk.isPending ? (recalculateRisk.variables ?? null) : null}
                />
              ) : (
                <KanbanBoard
                  risks={risks}
                  selectedRiskId={selectedRiskId}
                  onSelectRisk={setSelectedRiskId}
                  onDeleteRisk={setDeleteRiskId}
                  threatModelId={threatModelId}
                />
              )}
            </div>

            {/* Detail panel (table view only) */}
            {detailPanel && viewMode === 'table' && <div className="w-[45%] shrink-0">{detailPanel}</div>}
          </div>

          {/* Kept visible at one page too, once the size has been changed, so the
              control that got the user there can also take them back. */}
          {(pageCount > 1 || pageSize !== DEFAULT_RISK_PAGE_SIZE) && (
            <RegisterPagination
              page={page}
              pageCount={pageCount}
              pageSize={pageSize}
              onPageChange={goToPage}
              onPageSizeChange={changePageSize}
            />
          )}
        </>
      )}

      {/* Detail panel for the board (below it) */}
      {detailPanel && viewMode === 'kanban' && detailPanel}

      <AddRiskDialog
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
        threatModelId={threatModelId}
        componentThreats={componentThreats}
        owners={owners}
        scoringMethodKey={riskScoringMethod}
        scoringMethod={activeScoringMethod}
      />

      <AlertDialog open={deleteRiskId !== null} onOpenChange={(open) => !open && setDeleteRiskId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete risk</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently deletes the risk, its responses and its threat links. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} disabled={deleteRisk.isPending}>
              {deleteRisk.isPending ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
