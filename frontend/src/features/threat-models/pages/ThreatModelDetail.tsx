import { useState, useMemo, useRef, useEffect, useCallback } from 'react'
import { Link, Navigate, useLocation, useParams, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ChevronLeft, Loader2, LayoutDashboard, Shield, Trash2, BarChart3, FileText, Share2, Download, Pencil, Crosshair } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  ReferenceImageViewer,
  SystemContextModal,
  type SystemDialogTab,
  ManageThreatModelsModal,
  BlueprintSwitcher,
  ManageBlueprintsModal,
  type ManageBlueprintsMode,
  resolveSelectedBlueprintId,
  showsBlueprintChoice,
  ManagePacksModal,
  ManagePeopleModal,
  ViewFrameworksModal,
  RiskAnalysisTab,
} from '@/features/threat-models/components/workspace'
import { OverviewTab } from '@/features/threat-models/components/OverviewTab'
import { MagicLinkDialog } from '@/features/threat-models/components/MagicLinkDialog'
import { ReportView } from '@/features/reports/ReportView'
import { PentestView } from '@/features/pentests/PentestView'
import { useWorkspaceThreatAnalysis } from '@/features/threat-models/hooks'
import { useWorkspace } from '@/contexts/WorkspaceContext'
import { ComponentView } from '@/features/dfd-editor/components/threat-analysis/ComponentView'
import { UseCaseView } from '@/features/dfd-editor/components/threat-analysis/UseCaseView'
import type { UseCaseViewSelection } from '@/features/dfd-editor/components/threat-analysis/use-case-view-utils'
import { TableView } from '@/features/dfd-editor/components/threat-analysis/TableView'
import { OverdueCountermeasuresButton } from '@/features/dfd-editor/components/threat-analysis/OverdueCountermeasuresButton'
import { AddThreatDialog } from '@/features/dfd-editor/components/threat-analysis/AddThreatDialog'
import { AddCountermeasureDialog } from '@/features/dfd-editor/components/threat-analysis/AddCountermeasureDialog'
import { AddCustomComponentDialog } from '@/features/dfd-editor/components/threat-analysis/AddCustomComponentDialog'
import { useThreatModelThreats, type TargetRef } from '@/features/threat-models/api/threats'
import { useAnalysisComponents } from '@/features/threat-models/api/components'
import {
  canvasElementSelection,
  selectionTargetRef,
  threatHomeSelection,
  threatMatchesSelection,
  type AnalysisSelection,
} from '@/features/dfd-editor/components/threat-analysis/analysis-selection'
import { useModelTargets } from '@/features/dfd-editor/components/threat-analysis/useModelTargets'
import { toast } from 'sonner'
import type { ThreatModel, Diagram, ScoringMethodKey } from '@/types'
import type { AnalysisThreat } from '@/features/dfd-editor/types/threat-analysis'
import { cn } from '@/lib/utils'
import { api, ApiError } from '@/lib/api'
import {
  useThreatModel,
  useThreatModels,
  useDeleteThreatModel,
  useDeleteDFD,
  useUpdateThreatModel,
  useAddReferencedModel,
  useRemoveReferencedModel,
  useRemoveThreatModelPack,
  useAddThreatModelPack,
  exportCycloneDx,
} from '@/features/threat-models/api/threat-models'
import { usePacks } from '@/features/libraries/api/packs'
import { DeleteThreatModelDialog, DeleteDFDDialog } from '@/features/threat-models/components'
import { useReferenceImages, useUploadReferenceImage, useDeleteReferenceImage } from '@/features/threat-models/api/reference-images'
import {
  DEFAULT_MODEL_TAB,
  DEFAULT_THREAT_ANALYSIS_VIEW,
  THREAT_ANALYSIS_VIEWS,
  THREAT_MODEL_TABS,
  tabFromSlug,
  threatAnalysisViewPath,
  threatModelTabPath,
  type ThreatAnalysisView,
  type ThreatModelTab,
} from '@/features/threat-models/lib/model-tabs'

async function createDiagram(threatModelId: string, title: string, blueprintId: number | null): Promise<Diagram> {
  return api.post<Diagram>('/diagrams/create_for_threat_model/', {
    threatModelId,
    name: title,
    ...(blueprintId !== null ? { blueprintId } : {}),
    canvas_data: { nodes: [], edges: [], viewport: { x: 0, y: 0, zoom: 1 } },
  })
}

export function ThreatModelDetail() {
  const { id, tab: tabSlug, view: viewSlug } = useParams<{ id: string; tab?: string; view?: string }>()
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const { currentTeam, isSecurityTeam } = useWorkspace()

  // View state. The tab lives in the URL (one URL per sub-screen); tab clicks
  // push history so Back and Forward move between tabs, and the query string
  // (the selected blueprint) carries over.
  const activeTab = tabFromSlug(tabSlug, THREAT_MODEL_TABS)
  // Coming back to Threat Analysis returns to the view last used there.
  const lastThreatAnalysisView = useRef<ThreatAnalysisView>(DEFAULT_THREAT_ANALYSIS_VIEW)
  const goToTab = useCallback(
    (nextTab: ThreatModelTab) => {
      // The modal parameters belong to Threat Analysis; the blueprint carries over.
      const nextSearch = new URLSearchParams(location.search)
      nextSearch.delete('threat')
      nextSearch.delete('countermeasure')
      const searchString = nextSearch.toString()
      navigate({
        pathname:
          nextTab === 'threat-analysis'
            ? threatAnalysisViewPath(id!, lastThreatAnalysisView.current)
            : threatModelTabPath(id!, nextTab),
        search: searchString ? `?${searchString}` : '',
      })
    },
    [navigate, id, location.search]
  )
  // The Threat Analysis view lives in the URL too: /threat-analysis/components,
  // /use-cases or /table. A view change pushes history and keeps the blueprint;
  // `mutateSearch` adjusts the rest of the query string in the same navigation.
  const viewMode = tabFromSlug(viewSlug, THREAT_ANALYSIS_VIEWS)
  useEffect(() => {
    if (activeTab === 'threat-analysis' && viewMode) lastThreatAnalysisView.current = viewMode
  }, [activeTab, viewMode])
  const goToView = useCallback(
    (nextView: ThreatAnalysisView, mutateSearch?: (search: URLSearchParams) => void) => {
      const nextSearch = new URLSearchParams(location.search)
      mutateSearch?.(nextSearch)
      const searchString = nextSearch.toString()
      navigate({ pathname: threatAnalysisViewPath(id!, nextView), search: searchString ? `?${searchString}` : '' })
    },
    [navigate, id, location.search]
  )
  const [selectedDiagramId, setSelectedDiagramId] = useState<string | null>(null)
  // The selection is a target reference or the whole system, not a canvas id.
  const [selectedTarget, setSelectedTarget] = useState<AnalysisSelection | null>(null)
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null)
  // The "By use case" view's own selection: a use case or an abuse case.
  const [useCaseSelection, setUseCaseSelection] = useState<UseCaseViewSelection | null>(null)

  // Modal state
  const [systemContextModalOpen, setSystemContextModalOpen] = useState(false)
  const [systemDialogTab, setSystemDialogTab] = useState<SystemDialogTab>('details')
  const [manageBlueprintsOpen, setManageBlueprintsOpen] = useState(false)
  const [manageBlueprintsMode, setManageBlueprintsMode] = useState<ManageBlueprintsMode>('list')
  const [manageThreatModelsModalOpen, setManageThreatModelsModalOpen] = useState(false)
  const [managePacksModalOpen, setManagePacksModalOpen] = useState(false)
  const [managePeopleModalOpen, setManagePeopleModalOpen] = useState(false)
  const [viewFrameworksModalOpen, setViewFrameworksModalOpen] = useState(false)
  const [shareLinkDialogOpen, setShareLinkDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [deleteDFDDialogOpen, setDeleteDFDDialogOpen] = useState(false)
  const [dfdToDelete, setDfdToDelete] = useState<{ id: string; name: string } | null>(null)

  // Add threat/countermeasure dialog states
  const [addThreatDialogOpen, setAddThreatDialogOpen] = useState(false)
  const [addCountermeasureDialogOpen, setAddCountermeasureDialogOpen] = useState(false)
  const [addComponentDialogOpen, setAddComponentDialogOpen] = useState(false)

  // Inline name editing state
  const [isEditingName, setIsEditingName] = useState(false)
  const [nameValue, setNameValue] = useState('')
  const nameInputRef = useRef<HTMLInputElement>(null)

  // Reference image states
  const [referenceImageViewerOpen, setReferenceImageViewerOpen] = useState(false)
  const [selectedImageIndex, setSelectedImageIndex] = useState(0)

  // Mutations
  const deleteMutation = useDeleteThreatModel()
  const deleteDFDMutation = useDeleteDFD()
  const updateThreatModelMutation = useUpdateThreatModel()
  const addReferencedModelMutation = useAddReferencedModel()
  const removeReferencedModelMutation = useRemoveReferencedModel()
  const removePackMutation = useRemoveThreatModelPack()
  const addPackMutation = useAddThreatModelPack()

  // All imported packs (for add-back in ManagePacksModal)
  const { data: allImportedPacks = [] } = usePacks()

  // Reference images
  const { data: referenceImages = [] } = useReferenceImages(id || null)
  const uploadImageMutation = useUploadReferenceImage()
  const deleteImageMutation = useDeleteReferenceImage()


  // Data fetching
  const {
    data: threatModel,
    isLoading: isLoadingModel,
    isError: isErrorModel,
  } = useThreatModel(id!)

  const diagrams = useMemo(() => (threatModel?.dfds || []) as Diagram[], [threatModel?.dfds])

  // Blueprints (plan J2): the selected one lives in the URL query `blueprint`
  // and goes to the system context dialog and the DFD lists. The summary
  // cards and the threat tree cover every blueprint.
  const [searchParams, setSearchParams] = useSearchParams()
  const blueprints = useMemo(() => threatModel?.blueprints ?? [], [threatModel?.blueprints])
  const requestedBlueprint = searchParams.get('blueprint')
  const selectedBlueprintId = useMemo(
    () => resolveSelectedBlueprintId(requestedBlueprint ? Number(requestedBlueprint) : null, blueprints),
    [requestedBlueprint, blueprints]
  )
  const handleSelectBlueprint = useCallback(
    (blueprintId: number) => {
      setSearchParams(
        (current) => {
          const next = new URLSearchParams(current)
          next.set('blueprint', String(blueprintId))
          return next
        },
        { replace: true }
      )
      setSelectedDiagramId(null)
    },
    [setSearchParams]
  )
  const blueprintDiagrams = useMemo(() => {
    if (!showsBlueprintChoice(blueprints) || selectedBlueprintId === null) return diagrams
    const diagramIds = new Set(
      (threatModel?.dfds ?? [])
        .filter((dfd) => dfd.blueprint == null || dfd.blueprint === selectedBlueprintId)
        .map((dfd) => String(dfd.id))
    )
    return diagrams.filter((diagram) => diagramIds.has(String(diagram.id)))
  }, [diagrams, blueprints, selectedBlueprintId, threatModel?.dfds])

  const { data: allThreatModels = [] } = useThreatModels()

  // Fetch analysis-only components (linked directly to threat model, not via DFD canvas)
  const { data: analysisComponents = [] } = useAnalysisComponents(id ?? null)

  // The model's targets by key, for the selection's name (plan 11.3).
  const modelTargets = useModelTargets(id)

  // Workspace threat analysis state
  const {
    analysisThreats,
    progressChecklist,
    completionStatus,
    summaries,
    isLoadingThreats,
    updateCountermeasureStatus,
    updateCountermeasurePriority,
    updateCountermeasureDueDate,
    updateCountermeasureExternalTicket,
    assignOwner,
    updateTriageStatus,
    reorderThreats,
    reorderCountermeasures,
  } = useWorkspaceThreatAnalysis(id, diagrams, analysisComponents)

  const { data: analysisPayload, refetch: refetchThreats } = useThreatModelThreats(id)

  // The open threat and countermeasure modals live in the URL (`?threat=T17`,
  // `?countermeasure=C5`), written with replace so Back still leaves the tab.
  // One modal at a time: opening one drops the other.
  const openThreatNumber = searchParams.get('threat')
  const openCountermeasureNumber = searchParams.get('countermeasure')
  const setOpenDetail = useCallback(
    (parameter: 'threat' | 'countermeasure', displayNumber: string | null) => {
      setSearchParams(
        (current) => {
          const next = new URLSearchParams(current)
          next.delete('threat')
          next.delete('countermeasure')
          if (displayNumber) next.set(parameter, displayNumber)
          return next
        },
        { replace: true }
      )
    },
    [setSearchParams]
  )
  const handleOpenThreatChange = useCallback(
    (displayNumber: string | null) => setOpenDetail('threat', displayNumber),
    [setOpenDetail]
  )
  const handleOpenCountermeasureChange = useCallback(
    (displayNumber: string | null) => setOpenDetail('countermeasure', displayNumber),
    [setOpenDetail]
  )

  // Create diagram mutation
  const createDiagramMutation = useMutation({
    mutationFn: (title: string) => createDiagram(id!, title, selectedBlueprintId),
    onSuccess: (newDiagram) => {
      queryClient.invalidateQueries({ queryKey: ['threat-models', id] })
      navigate(`/threat-models/${id}/diagrams/${newDiagram.id}`)
    },
  })

  // The analysis screen builds its tree from the backend rows (ComponentView); this page
  // only filters the scenarios by the chosen diagram and holds the selection.
  const filteredComponentThreats = useMemo(() => {
    if (!selectedDiagramId) return analysisThreats
    return analysisThreats.filter(
      (ct) => ct.wholeSystem || ct.targets.some((target) => String(target.dfdId) === selectedDiagramId)
    )
  }, [analysisThreats, selectedDiagramId])

  const selectedComponentThreat = useMemo(() => {
    if (!selectedThreatId) return null
    return filteredComponentThreats.find((ct) => ct.id === selectedThreatId) || null
  }, [filteredComponentThreats, selectedThreatId])

  // What the Add threat dialog is preset with: the selection's target, or the whole system.
  const addThreatPreset = useMemo(() => {
    if (!selectedTarget) return null
    if (selectedTarget.kind === 'system') {
      return { targets: [] as TargetRef[], wholeSystem: true, name: 'System' }
    }
    const ref = selectionTargetRef(selectedTarget)!
    const option = modelTargets.byKey.get(`${ref.type}:${ref.id}`)
    return { targets: [ref], wholeSystem: false, name: option?.label ?? `${ref.type} ${ref.id}` }
  }, [selectedTarget, modelTargets.byKey])

  const selectedThreatBackendInfo = useMemo(() => {
    if (!selectedComponentThreat?.backendThreatId) return null
    return {
      backendId: selectedComponentThreat.backendThreatId,
      name: selectedComponentThreat.threatName || 'Unknown Threat',
      threatLibraryId: selectedComponentThreat.threatLibraryId,
      targets: selectedComponentThreat.targets.map((target): TargetRef => ({ type: target.type, id: target.id })),
    }
  }, [selectedComponentThreat])

  // A new tree selection in the "By use case" view clears the selected threat.
  const handleUseCaseSelectionChange = useCallback((selection: UseCaseViewSelection | null) => {
    setUseCaseSelection(selection)
    setSelectedThreatId(null)
  }, [])

  // The modal parameters belong to one view's list, so a view change drops them.
  const dropDetailParameters = (search: URLSearchParams) => {
    search.delete('threat')
    search.delete('countermeasure')
  }

  // "From abuse cases" links in a threat: show that abuse case in the "By Use Case" view.
  const handleOpenAbuseCase = useCallback(
    (abuseCaseId: number) => {
      setUseCaseSelection({ kind: 'abuseCase', abuseCaseId })
      setSelectedThreatId(null)
      goToView('use-cases', dropDetailParameters)
    },
    [goToView]
  )

  // The selected threat belongs to one view's list; clear it when the view changes.
  const handleViewModeChange = useCallback(
    (nextView: ThreatAnalysisView) => {
      if (nextView === viewMode) return
      setSelectedThreatId(null)
      goToView(nextView, dropDetailParameters)
    },
    [viewMode, goToView]
  )

  const handleAddBlueprint = useCallback(() => {
    setManageBlueprintsMode('add')
    setManageBlueprintsOpen(true)
  }, [])
  const handleManageBlueprints = useCallback(() => {
    setManageBlueprintsMode('list')
    setManageBlueprintsOpen(true)
  }, [])

  const handleSelectTarget = useCallback((selection: AnalysisSelection) => {
    setSelectedTarget((current) => {
      const changed = !current || JSON.stringify(current) !== JSON.stringify(selection)
      if (changed) setSelectedThreatId(null)
      return selection
    })
  }, [])

  // A deep link (`?threat=T17` or `?countermeasure=C5`) selects the threat
  // and, in the component view, the tree row it sits on, so its modal can
  // open. Applied once per link while rendering (React's "adjust state when
  // an input changes"), not in an effect.
  const deepLinkedThreat = useMemo(() => {
    if (activeTab !== 'threat-analysis') return null
    if (openThreatNumber) return analysisThreats.find((threat) => threat.displayNumber === openThreatNumber) ?? null
    if (!openCountermeasureNumber) return null
    const holdsCountermeasure = (threat: AnalysisThreat) =>
      threat.countermeasures.some((countermeasure) => countermeasure.displayNumber === openCountermeasureNumber)
    if (selectedComponentThreat && holdsCountermeasure(selectedComponentThreat)) return selectedComponentThreat
    return analysisThreats.find(holdsCountermeasure) ?? null
  }, [activeTab, openThreatNumber, openCountermeasureNumber, analysisThreats, selectedComponentThreat])
  const deepLinkKey = deepLinkedThreat ? `${openThreatNumber ?? ''}|${openCountermeasureNumber ?? ''}|${deepLinkedThreat.id}` : null
  const [appliedDeepLinkKey, setAppliedDeepLinkKey] = useState<string | null>(null)
  if (deepLinkedThreat && deepLinkKey !== appliedDeepLinkKey) {
    setAppliedDeepLinkKey(deepLinkKey)
    if (viewMode === 'components' && !threatMatchesSelection(deepLinkedThreat, selectedTarget)) {
      setSelectedTarget(threatHomeSelection(deepLinkedThreat))
    }
    if (selectedThreatId !== deepLinkedThreat.id) setSelectedThreatId(deepLinkedThreat.id)
  }

  // "Analyze Threats" in the DFD editor passes what was selected on the canvas
  // in the router state; start the tree there, once per visit.
  const canvasElementFromEditor = (location.state as { analysisCanvasElementId?: string } | null)?.analysisCanvasElementId
  const [appliedCanvasVisitKey, setAppliedCanvasVisitKey] = useState<string | null>(null)
  if (canvasElementFromEditor && analysisPayload && appliedCanvasVisitKey !== location.key) {
    setAppliedCanvasVisitKey(location.key)
    const canvasSelection = canvasElementSelection(canvasElementFromEditor, analysisPayload)
    // The DFD editor links straight to the components view.
    if (canvasSelection) {
      setSelectedTarget(canvasSelection)
      setSelectedThreatId(null)
    }
  }

  // Inline name editing handlers
  const handleExportCycloneDx = useCallback(async (threatModelId: string) => {
    try {
      const warnings = await exportCycloneDx(threatModelId)
      if (warnings.length > 0) {
        toast.warning('The export left some references out', {
          description: warnings.join('\n'),
        })
      }
    } catch {
      toast.error('Could not export the threat model')
    }
  }, [])

  const handleStartEditingName = useCallback(() => {
    if (threatModel) {
      setNameValue(threatModel.name)
      setIsEditingName(true)
    }
  }, [threatModel])

  useEffect(() => {
    if (isEditingName && nameInputRef.current) {
      nameInputRef.current.focus()
      nameInputRef.current.select()
    }
  }, [isEditingName])

  const handleSaveName = useCallback(() => {
    const trimmedName = nameValue.trim()
    if (trimmedName && trimmedName !== threatModel?.name && id) {
      updateThreatModelMutation.mutate({ id, data: { name: trimmedName } as Partial<ThreatModel> })
    }
    setIsEditingName(false)
  }, [nameValue, threatModel?.name, id, updateThreatModelMutation])

  const handleCancelEditName = useCallback(() => {
    setIsEditingName(false)
  }, [])

  const handleNameKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSaveName()
    } else if (e.key === 'Escape') {
      handleCancelEditName()
    }
  }, [handleSaveName, handleCancelEditName])

  // Handlers
  const handleCreateDFD = () => {
    const title = `Data Flow Diagram ${(diagrams?.length || 0) + 1}`
    createDiagramMutation.mutate(title)
  }



  const handleConfirmDeleteDFD = (deleteOrphanedComponents: boolean) => {
    if (dfdToDelete) {
      deleteDFDMutation.mutate(
        { dfdId: dfdToDelete.id, deleteOrphanedComponents },
        {
          onSuccess: () => {
            setDeleteDFDDialogOpen(false)
            setDfdToDelete(null)
            // Refresh threat model (includes diagrams via dfds field)
            queryClient.invalidateQueries({ queryKey: ['threat-models', id] })
          },
        }
      )
    }
  }

  const handleDeleteThreatModel = () => {
    if (id) {
      deleteMutation.mutate(id, {
        onSuccess: () => {
          setDeleteDialogOpen(false)
          navigate('/threat-models')
        },
      })
    }
  }

  const handleScoringMethodChange = (method: ScoringMethodKey) => {
    if (id) {
      updateThreatModelMutation.mutate({ id, data: { riskScoringMethod: method } as Partial<ThreatModel> })
    }
  }

  // A bare or unknown tab goes to the overview, keeping the query string and
  // the router state (the DFD editor's canvas selection rides in it).
  if (!activeTab) {
    return (
      <Navigate
        to={{ pathname: threatModelTabPath(id!, DEFAULT_MODEL_TAB), search: location.search }}
        state={location.state}
        replace
      />
    )
  }
  // Threat Analysis without a known view goes to the components view; any other tab takes no view.
  if (activeTab === 'threat-analysis' && !viewMode) {
    return (
      <Navigate
        to={{ pathname: threatAnalysisViewPath(id!, DEFAULT_THREAT_ANALYSIS_VIEW), search: location.search }}
        state={location.state}
        replace
      />
    )
  }
  if (activeTab !== 'threat-analysis' && viewSlug) {
    return <Navigate to={{ pathname: threatModelTabPath(id!, activeTab), search: location.search }} replace />
  }

  // Loading state
  if (isLoadingModel) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  // Error state
  if (isErrorModel || !threatModel) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <p className="text-muted-foreground">Threat model not found</p>
        <Button onClick={() => navigate('/')}>Go to Dashboard</Button>
      </div>
    )
  }

  // 45px: the navbar is h-11 plus its 1px bottom border; 44px left the page 1px too tall.
  return (
    <div className="flex flex-col h-[calc(100vh-45px)]">
      {/* Compact Header */}
      <div className="flex-shrink-0 bg-background border-b">
        <div className="flex items-center justify-between px-4 py-2">
          {/* Left: Breadcrumb + Title */}
          <div className="flex items-center gap-3 min-w-0">
            <Link
              to="/threat-models"
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <ChevronLeft className="h-3 w-3" />
              {threatModel.organizationName ?? 'Threat Models'}
            </Link>
            {threatModel.businessUnitName && (
              <>
                <span className="text-muted-foreground">/</span>
                <span className="text-xs text-muted-foreground">{threatModel.businessUnitName}</span>
              </>
            )}
            {threatModel.owningTeamName && (
              <>
                <span className="text-muted-foreground">/</span>
                <span className="text-xs text-muted-foreground">{threatModel.owningTeamName}</span>
              </>
            )}
            <span className="text-muted-foreground">/</span>
            {isEditingName ? (
              <input
                ref={nameInputRef}
                type="text"
                value={nameValue}
                onChange={(e) => setNameValue(e.target.value)}
                onBlur={handleSaveName}
                onKeyDown={handleNameKeyDown}
                className="font-semibold bg-transparent border-b border-primary outline-none px-0 py-0 max-w-[300px]"
              />
            ) : (
              <button
                onClick={handleStartEditingName}
                className="font-semibold truncate hover:text-primary group flex items-center gap-1 cursor-pointer"
                title="Click to rename"
              >
                {threatModel.name}
                <Pencil className="h-3 w-3 opacity-0 group-hover:opacity-100 touch:opacity-100 transition-opacity text-muted-foreground" />
              </button>
            )}
            <span className="text-muted-foreground">/</span>
            <span className="text-sm text-muted-foreground">Workspace</span>
            <BlueprintSwitcher
              blueprints={blueprints}
              selectedBlueprintId={selectedBlueprintId}
              onSelect={handleSelectBlueprint}
              onAddBlueprint={handleAddBlueprint}
              onManageBlueprints={handleManageBlueprints}
            />
          </div>

          {/* Right: Actions */}
          <div className="flex items-center gap-3">
            {/* Share button */}
            <Button
              variant="outline"
              size="sm"
              className="h-7 px-2 text-xs gap-1"
              onClick={() => setShareLinkDialogOpen(true)}
            >
              <Share2 className="h-3 w-3" />
              <span className="hidden sm:inline">Share</span>
            </Button>

            {/* Export button */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 px-2 text-xs gap-1"
                >
                  <Download className="h-3 w-3" />
                  <span className="hidden sm:inline">Export</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem
                  onClick={() => id && handleExportCycloneDx(id)}
                  className="text-xs"
                >
                  CycloneDX 2.0 BOM
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            {/* Delete button */}
            <Button
              variant="outline"
              size="sm"
              className="h-7 px-2 text-xs gap-1 text-red-600 hover:text-red-700 hover:bg-red-50"
              onClick={() => setDeleteDialogOpen(true)}
            >
              <Trash2 className="h-3 w-3" />
              <span className="hidden sm:inline">Delete</span>
            </Button>

          </div>
        </div>
      </div>

      {/* Tab-based Content */}
      {/* Manual activation: with automatic, Radix fires onValueChange on mouse
          down and again on focus, which would push two history entries. */}
      <Tabs
        value={activeTab}
        onValueChange={(value) => goToTab(value as ThreatModelTab)}
        activationMode="manual"
        className="flex-1 flex flex-col min-h-0"
      >
        <div className="border-b bg-muted/30 px-6">
          <div className="flex items-center justify-between">
            <TabsList className="h-12 bg-transparent p-0 gap-4">
            <TabsTrigger
              value="overview"
              className="h-12 px-4 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none gap-2"
            >
              <LayoutDashboard className="h-4 w-4" />
              Overview
            </TabsTrigger>
            <TabsTrigger
              value="threat-analysis"
              className="h-12 px-4 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none gap-2"
            >
              <Shield className="h-4 w-4" />
              Threat Analysis
              {summaries.threatSummary.exposed > 0 && (
                <span className="ml-1 px-1.5 py-0.5 text-xs bg-red-100 text-red-700 rounded-full">
                  {summaries.threatSummary.exposed}
                </span>
              )}
            </TabsTrigger>
            <TabsTrigger
              value="risk-analysis"
              className="h-12 px-4 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none gap-2"
            >
              <BarChart3 className="h-4 w-4" />
              Risk Analysis
            </TabsTrigger>
            <TabsTrigger
              value="pentests"
              className="h-12 px-4 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none gap-2"
            >
              <Crosshair className="h-4 w-4" />
              Pentests
            </TabsTrigger>
            <TabsTrigger
              value="reports"
              className="h-12 px-4 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none gap-2"
            >
              <FileText className="h-4 w-4" />
              Reports
            </TabsTrigger>
          </TabsList>
            <button
              onClick={() => setViewFrameworksModalOpen(true)}
              className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
            >
              <Shield className="h-4 w-4" />
              Compliance
            </button>
          </div>
        </div>

        {/* Overview Tab */}
        <TabsContent value="overview" className="flex-1 overflow-auto m-0 p-6">
          <OverviewTab
            threatModel={threatModel}
            blueprints={blueprints}
            selectedBlueprintId={selectedBlueprintId}
            diagrams={blueprintDiagrams}
            progressChecklist={progressChecklist}
            completionStatus={completionStatus}
            selectedDiagramId={selectedDiagramId}
            referenceImages={referenceImages}
            isCreatingDiagram={createDiagramMutation.isPending}
            isUploadingImage={uploadImageMutation.isPending}
            isSecurityTeam={isSecurityTeam}
            onSelectBlueprint={handleSelectBlueprint}
            onAddBlueprint={handleAddBlueprint}
            onManageBlueprints={handleManageBlueprints}
            onSelectDiagram={setSelectedDiagramId}
            onEditDiagram={(diagramId) => navigate(`/threat-models/${id}/diagrams/${diagramId}`)}
            onCreateDiagram={handleCreateDFD}
            onUploadImage={async (file, description) => {
              await uploadImageMutation.mutateAsync({
                threatModelId: id!,
                file,
                description,
              })
            }}
            onDeleteImage={async (imageId) => {
              await deleteImageMutation.mutateAsync(imageId)
            }}
            onImageClick={(index) => {
              setSelectedImageIndex(index)
              setReferenceImageViewerOpen(true)
            }}
            onManageThreatModels={() => setManageThreatModelsModalOpen(true)}
            onManagePacks={() => setManagePacksModalOpen(true)}
            onManagePeople={() => setManagePeopleModalOpen(true)}
            onOpenSystem={(tab) => {
              setSystemDialogTab(tab)
              setSystemContextModalOpen(true)
            }}
          />
        </TabsContent>

        {/* Threat Analysis Tab */}
        <TabsContent value="threat-analysis" className="flex-1 flex flex-col m-0 min-h-0">
          {isLoadingThreats ? (
            <div className="flex-1 flex items-center justify-center">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <>
              {/* DFD Filter + View Toggle Bar */}
              <div className="flex items-center justify-between px-4 py-2 border-b bg-muted/30 flex-shrink-0">
                <div className="flex items-center gap-4">
                  <h2 className="font-semibold">Threat Analysis</h2>
                  {/* DFD Filter - only show if DFDs exist */}
                  {blueprintDiagrams.length > 0 && (
                    <div className="flex items-center gap-2">
                      <select
                        value={selectedDiagramId || ''}
                        onChange={(e) => setSelectedDiagramId(e.target.value || null)}
                        className="text-sm border rounded-md px-2 py-1 bg-background"
                      >
                        <option value="">All</option>
                        {blueprintDiagrams.map((d) => (
                          <option key={d.id} value={d.id}>
                            {d.name}{!d.isPrimary ? ' (Reference)' : ''}
                          </option>
                        ))}
                      </select>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7 text-xs"
                        onClick={() => {
                          const diagramId =
                            selectedDiagramId || blueprintDiagrams.find((d) => d.isPrimary)?.id || blueprintDiagrams[0].id
                          navigate(`/threat-models/${id}/diagrams/${diagramId}`)
                        }}
                      >
                        DFD
                      </Button>
                    </div>
                  )}
                  {/* Every overdue countermeasure of the model; shows only when something is overdue. */}
                  <OverdueCountermeasuresButton
                    threatModelId={id!}
                    onOpenCountermeasure={(displayNumber) =>
                      goToView('components', (search) => {
                        dropDetailParameters(search)
                        search.set('countermeasure', displayNumber)
                      })
                    }
                  />
                </div>
                <div className="flex items-center rounded-lg border bg-background p-1">
                  <Button
                    variant={viewMode === 'components' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => handleViewModeChange('components')}
                    className={cn(
                      'rounded-md px-3',
                      viewMode === 'components' ? '' : 'hover:bg-transparent'
                    )}
                  >
                    Component View
                  </Button>
                  <Button
                    variant={viewMode === 'use-cases' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => handleViewModeChange('use-cases')}
                    className={cn(
                      'rounded-md px-3',
                      viewMode === 'use-cases' ? '' : 'hover:bg-transparent'
                    )}
                  >
                    By Use Case
                  </Button>
                  <Button
                    variant={viewMode === 'table' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => handleViewModeChange('table')}
                    className={cn(
                      'rounded-md px-3',
                      viewMode === 'table' ? '' : 'hover:bg-transparent'
                    )}
                  >
                    Table View
                  </Button>
                </div>
              </div>

              {/* Threat Analysis Content - fills remaining space */}
              <div className="flex-1 min-h-0">
                {viewMode === 'use-cases' ? (
                  <UseCaseView
                    threatModelId={id!}
                    threats={filteredComponentThreats}
                    allThreats={analysisThreats}
                    selection={useCaseSelection}
                    onSelectionChange={handleUseCaseSelectionChange}
                    selectedThreatId={selectedThreatId}
                    selectedThreat={selectedComponentThreat}
                    onSelectThreat={setSelectedThreatId}
                    openThreatNumber={openThreatNumber}
                    onOpenThreatChange={handleOpenThreatChange}
                    openCountermeasureNumber={openCountermeasureNumber}
                    onOpenCountermeasureChange={handleOpenCountermeasureChange}
                    onOpenAbuseCase={handleOpenAbuseCase}
                    onCountermeasureStatusChange={updateCountermeasureStatus}
                    onAssignOwner={assignOwner}
                    onUpdateTriageStatus={updateTriageStatus}
                    onAddCustomCountermeasure={() => setAddCountermeasureDialogOpen(true)}
                    onCountermeasurePriorityChange={updateCountermeasurePriority}
                    onCountermeasureDueDateChange={updateCountermeasureDueDate}
                    onCountermeasureExternalTicketChange={updateCountermeasureExternalTicket}
                    onReorderCountermeasures={reorderCountermeasures}
                    isSecurityTeam={isSecurityTeam}
                  />
                ) : viewMode === 'components' ? (
                  <ComponentView
                    threatModelId={id!}
                    threats={filteredComponentThreats}
                    selection={selectedTarget}
                    selectedThreatId={selectedThreatId}
                    selectedThreat={selectedComponentThreat}
                    onSelectTarget={handleSelectTarget}
                    onSelectThreat={setSelectedThreatId}
                    openThreatNumber={openThreatNumber}
                    onOpenThreatChange={handleOpenThreatChange}
                    openCountermeasureNumber={openCountermeasureNumber}
                    onOpenCountermeasureChange={handleOpenCountermeasureChange}
                    onOpenAbuseCase={handleOpenAbuseCase}
                    onCountermeasureStatusChange={updateCountermeasureStatus}
                    onAssignOwner={assignOwner}
                    onAddComponent={() => setAddComponentDialogOpen(true)}
                    onAddCustomThreat={() => setAddThreatDialogOpen(true)}
                    onUpdateTriageStatus={updateTriageStatus}
                    onAddCustomCountermeasure={() => setAddCountermeasureDialogOpen(true)}
                    onCountermeasurePriorityChange={updateCountermeasurePriority}
                    onCountermeasureDueDateChange={updateCountermeasureDueDate}
                    onCountermeasureExternalTicketChange={updateCountermeasureExternalTicket}
                    onReorderThreats={reorderThreats}
                    onReorderCountermeasures={reorderCountermeasures}
                    isSecurityTeam={isSecurityTeam}
                  />
                ) : (
                  <TableView
                    threats={filteredComponentThreats}
                    onSelectThreat={(threat) => {
                      if (!threatMatchesSelection(threat, selectedTarget)) setSelectedTarget(threatHomeSelection(threat))
                      setSelectedThreatId(threat.id)
                      // One navigation: the components view with this threat's modal open.
                      goToView('components', (search) => {
                        dropDetailParameters(search)
                        search.set('threat', threat.displayNumber)
                      })
                    }}
                  />
                )}
              </div>
            </>
          )}
        </TabsContent>

        {/* Risk Analysis Tab */}
        <TabsContent value="risk-analysis" className="flex-1 overflow-auto m-0">
          <RiskAnalysisTab
            threatModelId={id!}
            analysisThreats={analysisThreats}
            riskScoringMethod={threatModel.riskScoringMethod ?? 'qualitative-matrix'}
            onScoringMethodChange={handleScoringMethodChange}
          />
        </TabsContent>

        {/* Pentests Tab */}
        <TabsContent value="pentests" className="flex-1 flex flex-col m-0 overflow-hidden">
          <PentestView threatModelId={id!} />
        </TabsContent>

        {/* Reports Tab */}
        <TabsContent value="reports" className="flex-1 flex flex-col m-0 overflow-hidden">
          <ReportView threatModelId={id!} />
        </TabsContent>
      </Tabs>

      {/* Modals */}
      <SystemContextModal
        open={systemContextModalOpen}
        onOpenChange={setSystemContextModalOpen}
        initialTab={systemDialogTab}
        threatModelId={id!}
        blueprints={blueprints}
        selectedBlueprintId={selectedBlueprintId}
      />

      <ManageThreatModelsModal
        open={manageThreatModelsModalOpen}
        onOpenChange={setManageThreatModelsModalOpen}
        relatedModels={threatModel.relatedModels ?? []}
        availableModels={allThreatModels.filter((m) => String(m.id) !== id)}
        currentModelId={id!}
        isAdding={addReferencedModelMutation.isPending}
        onAdd={async (targetModelId, relationType) => {
          try {
            await addReferencedModelMutation.mutateAsync({ threatModelId: id!, targetModelId, relationType })
          } catch (error) {
            // The backend answers 400 with `{error}` for a self link or a loop (plan J15).
            const body = error instanceof ApiError ? (error.data as { error?: string } | undefined) : undefined
            throw new Error(body?.error ?? (error instanceof Error ? error.message : 'Could not link the model'))
          }
        }}
        onRemove={(targetModelId, relationType) =>
          removeReferencedModelMutation.mutate({ threatModelId: id!, targetModelId, relationType })
        }
      />

      <ManageBlueprintsModal
        open={manageBlueprintsOpen}
        onOpenChange={setManageBlueprintsOpen}
        threatModelId={id!}
        blueprints={blueprints}
        initialMode={manageBlueprintsMode}
        onDeleted={(deletedBlueprintId) => {
          if (deletedBlueprintId === selectedBlueprintId) {
            setSearchParams(
              (current) => {
                const next = new URLSearchParams(current)
                next.delete('blueprint')
                return next
              },
              { replace: true }
            )
          }
        }}
      />

      <ManagePacksModal
        open={managePacksModalOpen}
        onOpenChange={setManagePacksModalOpen}
        connectedPacks={(threatModel.connectedPacks ?? []).filter(
          (p) => p.packType !== 'taxonomy' && p.packType !== 'compliance'
        )}
        availablePacks={allImportedPacks
          .filter((p) => p.packType !== 'taxonomy' && p.packType !== 'compliance')
          .map((p) => ({
            id: p.id,
            name: p.name,
            slug: p.slug,
            version: p.version,
            packType: p.packType,
          }))}
        onRemove={async (packId) => {
          const response = await removePackMutation.mutateAsync({ threatModelId: id!, packId })
          return response.dependencyWarnings ?? []
        }}
        onAdd={(packId) => addPackMutation.mutate({ threatModelId: id!, packId })}
      />

      <ManagePeopleModal
        open={managePeopleModalOpen}
        onOpenChange={setManagePeopleModalOpen}
        teamId={currentTeam?.id ?? 0}
        teamName={currentTeam?.name}
      />

      <ViewFrameworksModal
        open={viewFrameworksModalOpen}
        onOpenChange={setViewFrameworksModalOpen}
        frameworks={threatModel.frameworks || []}
      />

      <DeleteThreatModelDialog
        threatModel={threatModel}
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        onConfirm={handleDeleteThreatModel}
        isDeleting={deleteMutation.isPending}
      />

      <DeleteDFDDialog
        dfdId={dfdToDelete?.id ?? null}
        dfdName={dfdToDelete?.name ?? ''}
        isPrimary={diagrams.find(d => String(d.id) === dfdToDelete?.id)?.isPrimary ?? false}
        remainingDfdCount={diagrams.length - 1}
        open={deleteDFDDialogOpen}
        onOpenChange={(open: boolean) => {
          setDeleteDFDDialogOpen(open)
          if (!open) setDfdToDelete(null)
        }}
        onConfirm={handleConfirmDeleteDFD}
        isDeleting={deleteDFDMutation.isPending}
      />

      <MagicLinkDialog
        threatModelId={parseInt(id!, 10)}
        threatModelName={threatModel.name}
        open={shareLinkDialogOpen}
        onOpenChange={setShareLinkDialogOpen}
      />

      {/* Add Threat Dialog */}
      {addThreatPreset && (
        <AddThreatDialog
          open={addThreatDialogOpen}
          onOpenChange={setAddThreatDialogOpen}
          initialTargets={addThreatPreset.targets}
          initialWholeSystem={addThreatPreset.wholeSystem}
          targetName={addThreatPreset.name}
          threatModelId={id}
          onSuccess={() => {
            refetchThreats()
          }}
        />
      )}

      {/* Add Countermeasure Dialog */}
      {selectedThreatBackendInfo && (
        <AddCountermeasureDialog
          open={addCountermeasureDialogOpen}
          onOpenChange={setAddCountermeasureDialogOpen}
          threatId={selectedThreatBackendInfo.backendId}
          threatName={selectedThreatBackendInfo.name}
          threatLibraryId={selectedThreatBackendInfo.threatLibraryId}
          threatModelId={id}
          initialTargets={selectedThreatBackendInfo.targets}
          onSuccess={() => {
            refetchThreats()
          }}
        />
      )}

      {/* Add Custom Component Dialog */}
      <AddCustomComponentDialog
        open={addComponentDialogOpen}
        onOpenChange={setAddComponentDialogOpen}
        threatModelId={id!}
        blueprintId={selectedBlueprintId ?? undefined}
        onSuccess={() => {
          refetchThreats()
        }}
      />

      {/* Reference Image Viewer */}
      <ReferenceImageViewer
        images={referenceImages}
        initialIndex={selectedImageIndex}
        open={referenceImageViewerOpen}
        onOpenChange={setReferenceImageViewerOpen}
      />
    </div>
  )
}
