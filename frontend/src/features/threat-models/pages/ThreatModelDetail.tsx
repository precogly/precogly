import { useState, useMemo, useRef, useEffect, useCallback } from 'react'
import { Link, useParams, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ChevronLeft, Loader2, LayoutDashboard, Shield, Trash2, BarChart3, FileText, Share2, Download, Pencil, Crosshair, MoreHorizontal } from 'lucide-react'
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
import { TableView } from '@/features/dfd-editor/components/threat-analysis/TableView'
import { AddThreatDialog } from '@/features/dfd-editor/components/threat-analysis/AddThreatDialog'
import { AddCountermeasureDialog } from '@/features/dfd-editor/components/threat-analysis/AddCountermeasureDialog'
import { AddCustomComponentDialog } from '@/features/dfd-editor/components/threat-analysis/AddCustomComponentDialog'
import { ManagePersonasDialog } from '@/features/dfd-editor/components/threat-analysis/ManagePersonasDialog'
import { useThreatModelThreats, type TargetRef } from '@/features/threat-models/api/threats'
import { useAnalysisComponents } from '@/features/threat-models/api/components'
import {
  SYSTEM_SELECTION,
  selectionTargetRef,
  targetSelection,
  threatMatchesSelection,
  type AnalysisSelection,
} from '@/features/dfd-editor/components/threat-analysis/analysis-selection'
import { useModelTargets } from '@/features/dfd-editor/components/threat-analysis/useModelTargets'
import { toast } from 'sonner'
import type { ThreatModel, Diagram, ScoringMethodKey } from '@/types'
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

async function createDiagram(threatModelId: string, title: string, blueprintId: number | null): Promise<Diagram> {
  return api.post<Diagram>('/diagrams/create_for_threat_model/', {
    threatModelId,
    name: title,
    ...(blueprintId !== null ? { blueprintId } : {}),
    canvas_data: { nodes: [], edges: [], viewport: { x: 0, y: 0, zoom: 1 } },
  })
}

type ViewMode = 'component' | 'table'

export function ThreatModelDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { currentTeam, isSecurityTeam } = useWorkspace()

  // View state
  const [activeTab, setActiveTab] = useState<string>('overview')
  const [viewMode, setViewMode] = useState<ViewMode>('component')
  const [managePersonasOpen, setManagePersonasOpen] = useState(false)
  const [selectedDiagramId, setSelectedDiagramId] = useState<string | null>(null)
  // The selection is a target reference or the whole system, not a canvas id.
  const [selectedTarget, setSelectedTarget] = useState<AnalysisSelection | null>(null)
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null)

  // Modal state
  const [systemContextModalOpen, setSystemContextModalOpen] = useState(false)
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

  const { refetch: refetchThreats } = useThreatModelThreats(id)

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
    const parsedId = selectedComponentThreat.threatId.startsWith('lib-')
      ? parseInt(selectedComponentThreat.threatId.slice(4), 10)
      : null
    return {
      backendId: selectedComponentThreat.backendThreatId,
      name: selectedComponentThreat.threatName || 'Unknown Threat',
      threatLibraryId: parsedId != null && !Number.isNaN(parsedId) ? parsedId : null,
      targets: selectedComponentThreat.targets.map((target): TargetRef => ({ type: target.type, id: target.id })),
    }
  }, [selectedComponentThreat])

  const handleSelectTarget = useCallback((selection: AnalysisSelection) => {
    setSelectedTarget((current) => {
      const changed = !current || JSON.stringify(current) !== JSON.stringify(selection)
      if (changed) setSelectedThreatId(null)
      return selection
    })
  }, [])

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

  return (
    <div className="flex flex-col h-[calc(100vh-44px)]">
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
              onAddBlueprint={() => {
                setManageBlueprintsMode('add')
                setManageBlueprintsOpen(true)
              }}
              onManageBlueprints={() => {
                setManageBlueprintsMode('list')
                setManageBlueprintsOpen(true)
              }}
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

            {/* Model menu */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 px-2 text-xs gap-1"
                  aria-label="Model menu"
                >
                  <MoreHorizontal className="h-3 w-3" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem
                  onClick={() => setManagePersonasOpen(true)}
                  className="text-xs"
                >
                  Manage personas
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
      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col min-h-0">
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
              value="threats"
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
            diagrams={blueprintDiagrams}
            progressChecklist={progressChecklist}
            completionStatus={completionStatus}
            summaries={summaries}
            selectedDiagramId={selectedDiagramId}
            referenceImages={referenceImages}
            isCreatingDiagram={createDiagramMutation.isPending}
            isUploadingImage={uploadImageMutation.isPending}
            isSecurityTeam={isSecurityTeam}
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
            onEditSystemContext={() => setSystemContextModalOpen(true)}
            onNavigateToThreats={() => setActiveTab('threats')}
          />
        </TabsContent>

        {/* Threat Analysis Tab */}
        <TabsContent value="threats" className="flex-1 flex flex-col m-0 min-h-0">
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
                </div>
                <div className="flex items-center rounded-lg border bg-background p-1">
                  <Button
                    variant={viewMode === 'component' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setViewMode('component')}
                    className={cn(
                      'rounded-md px-3',
                      viewMode === 'component' ? '' : 'hover:bg-transparent'
                    )}
                  >
                    Component View
                  </Button>
                  <Button
                    variant={viewMode === 'table' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setViewMode('table')}
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
                {viewMode === 'component' ? (
                  <ComponentView
                    threatModelId={id!}
                    threats={filteredComponentThreats}
                    selection={selectedTarget}
                    selectedThreatId={selectedThreatId}
                    selectedThreat={selectedComponentThreat}
                    onSelectTarget={handleSelectTarget}
                    onSelectThreat={setSelectedThreatId}
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
                      const firstTarget = threat.targets[0]
                      const selection =
                        threat.wholeSystem || !firstTarget ? SYSTEM_SELECTION : targetSelection(firstTarget.type, firstTarget.id)
                      if (!threatMatchesSelection(threat, selectedTarget)) setSelectedTarget(selection)
                      setSelectedThreatId(threat.id)
                      setViewMode('component')
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
      <ManagePersonasDialog
        open={managePersonasOpen}
        onOpenChange={setManagePersonasOpen}
        threatModelId={id!}
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
