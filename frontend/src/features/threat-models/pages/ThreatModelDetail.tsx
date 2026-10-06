import { useState, useMemo, useRef, useEffect, useCallback } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
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
  ManageSystemsModal,
  ManageThreatModelsModal,
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
import { ReviewZoneProtectionsDialog } from '@/features/dfd-editor/components/threat-analysis/ReviewZoneProtectionsDialog'
import { useThreatModelThreats } from '@/features/threat-models/api/threats'
import { useAnalysisComponents, useTrustZones } from '@/features/threat-models/api/components'
import type { ThreatModel, Diagram, ScoringMethodKey } from '@/types'
import type { DiagramNode, DataFlowEdge, CanvasData } from '@/features/dfd-editor/types'
import { cn } from '@/lib/utils'
import { api } from '@/lib/api'
import {
  useThreatModel,
  useThreatModels,
  useSystems,
  useDeleteThreatModel,
  useDeleteDFD,
  useUpdateThreatModel,
  useAddThreatModelSystem,
  useRemoveThreatModelSystem,
  useAddReferencedModel,
  useRemoveReferencedModel,
  useRemoveThreatModelPack,
  useAddThreatModelPack,
  exportTmLibrary,
  exportCycloneDx,
} from '@/features/threat-models/api/threat-models'
import { usePacks } from '@/features/libraries/api/packs'
import { DeleteThreatModelDialog, DeleteDFDDialog } from '@/features/threat-models/components'
import { useReferenceImages, useUploadReferenceImage, useDeleteReferenceImage } from '@/features/threat-models/api/reference-images'

async function createDiagram(threatModelId: string, title: string): Promise<Diagram> {
  return api.post<Diagram>('/diagrams/create_for_threat_model/', {
    threatModelId,
    name: title,
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
  const [selectedDiagramId, setSelectedDiagramId] = useState<string | null>(null)
  const [selectedComponentId, setSelectedComponentId] = useState<string | null>(null)
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null)

  // Modal state
  const [systemContextModalOpen, setSystemContextModalOpen] = useState(false)
  const [manageSystemsModalOpen, setManageSystemsModalOpen] = useState(false)
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
  const [zoneProtectionsDialogOpen, setZoneProtectionsDialogOpen] = useState(false)

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
  const addSystemMutation = useAddThreatModelSystem()
  const removeSystemMutation = useRemoveThreatModelSystem()
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

  const { data: systems = [] } = useSystems()

  const { data: allThreatModels = [] } = useThreatModels()

  // Fetch analysis-only components (linked directly to threat model, not via DFD canvas)
  const { data: analysisComponents = [] } = useAnalysisComponents(id ?? null)

  // Fetch trust zones for this threat model (used for models without DFD canvas)
  const { data: backendTrustZones = [] } = useTrustZones(id)

  // Workspace threat analysis state
  const {
    componentThreats,
    progressChecklist,
    completionStatus,
    summaries,
    isLoadingThreats,
    revertInheritedCountermeasure,
    updateCountermeasureStatus,
    updateCountermeasurePriority,
    updateCountermeasureDueDate,
    updateCountermeasureExternalTicket,
    assignOwner,
    updateTriageStatus,
    reorderThreats,
    reorderCountermeasures,
  } = useWorkspaceThreatAnalysis(id, diagrams, analysisComponents)

  // Fetch threat model threats data (for nodeComponentMap)
  const { data: threatData, refetch: refetchThreats } = useThreatModelThreats(id)
  const nodeComponentMap = useMemo(() => threatData?.nodeComponentMap || {}, [threatData?.nodeComponentMap])

  // Create diagram mutation
  const createDiagramMutation = useMutation({
    mutationFn: (title: string) => createDiagram(id!, title),
    onSuccess: (newDiagram) => {
      queryClient.invalidateQueries({ queryKey: ['threat-models', id] })
      navigate(`/threat-models/${id}/diagrams/${newDiagram.id}`)
    },
  })

  // Get linked systems (use String() because systemIds are strings from serializer but s.id may be number at runtime)
  const linkedSystems = useMemo(() => {
    return systems.filter((s) => threatModel?.systemIds?.includes(String(s.id)))
  }, [systems, threatModel?.systemIds])

  // Get referenced threat models (use String() because referencedModelIds are strings from serializer but m.id may be number at runtime)
  const referencedModels = useMemo(() => {
    return allThreatModels.filter((m) =>
      threatModel?.referencedModelIds?.includes(String(m.id))
    )
  }, [allThreatModels, threatModel?.referencedModelIds])

  // Aggregate canvas data from all diagrams or selected diagram
  const aggregatedCanvasData = useMemo((): CanvasData => {
    const diagramsToUse = selectedDiagramId
      ? diagrams.filter((d) => String(d.id) === selectedDiagramId)
      : diagrams.filter((d) => d.isPrimary)

    const nodes: DiagramNode[] = []
    const edges: DataFlowEdge[] = []

    diagramsToUse.forEach((diagram) => {
      const canvasData = diagram.canvasData
      if (canvasData) {
        nodes.push(...(canvasData.nodes || []))
        edges.push(...(canvasData.edges || []))
      }
    })

    return { nodes, edges }
  }, [diagrams, selectedDiagramId])

  // Filter component threats by selected diagram
  const filteredComponentThreats = useMemo(() => {
    if (!selectedDiagramId) return componentThreats
    return componentThreats.filter(
      (ct) => String(ct.sourceDiagramId) === selectedDiagramId || String(ct.diagramId) === selectedDiagramId
    )
  }, [componentThreats, selectedDiagramId])

  // Get analyzable components, trust boundaries, and data flows
  const analyzableComponents = useMemo(() => {
    // Get components from DFD canvas nodes
    const canvasComponents = aggregatedCanvasData.nodes.filter(
      (node) => node.type === 'process' || node.type === 'datastore' ||
        node.type === 'humanActor' || node.type === 'systemActor'
    )

    // Get IDs of components already on canvas to avoid duplicates
    const canvasComponentIds = new Set(
      canvasComponents
        .map((node) => node.data?.componentId)
        .filter(Boolean)
    )

    // Create synthetic DiagramNode objects for analysis-only components
    // Only include components not already on canvas (when not filtering by specific DFD)
    const analysisOnlyNodes: DiagramNode[] = !selectedDiagramId
      ? analysisComponents
          .filter((comp) => !canvasComponentIds.has(comp.id))
          .map((comp) => ({
            id: `analysis-${comp.id}`,
            type: comp.category === 'process' ? 'process' :
                  comp.category === 'datastore' ? 'datastore' :
                  comp.category === 'external_human_actor' ? 'humanActor' :
                  comp.category === 'external_system_actor' ? 'systemActor' : 'process',
            position: { x: 0, y: 0 },
            data: {
              label: comp.name,
              componentId: comp.id,
              isAnalysisOnly: true,
            },
          }))
      : []

    return [...canvasComponents, ...analysisOnlyNodes]
  }, [aggregatedCanvasData.nodes, analysisComponents, selectedDiagramId])

  const trustZones = useMemo((): DiagramNode[] => {
    const canvasZones = aggregatedCanvasData.nodes.filter((node) => node.type === 'trustZone')
    if (canvasZones.length > 0) return canvasZones

    // For models without DFD canvas (e.g., imported TM-Library), derive zones from backend
    return backendTrustZones.map((zone) => ({
      id: `analysis-zone-${zone.id}`,
      type: 'trustZone',
      position: { x: 0, y: 0 },
      data: { label: zone.name },
    }))
  }, [aggregatedCanvasData.nodes, backendTrustZones])

  const dataFlows = useMemo(() => {
    if (aggregatedCanvasData.edges.length > 0) return aggregatedCanvasData.edges

    // For models without DFD canvas, derive flows from the edge_dataflow_map
    const edgeMap = threatData?.edgeDataflowMap || {}
    const syntheticEdges: DataFlowEdge[] = Object.entries(edgeMap).map(([edgeId, entry]) => ({
      id: edgeId,
      source: entry.sourceComponentName || '',
      target: entry.destComponentName || '',
      type: 'dataFlow' as const,
      data: {
        label: entry.label || 'Data Flow',
        dataflowId: entry.dataflowId,
      },
    }))
    return syntheticEdges
  }, [aggregatedCanvasData.edges, threatData?.edgeDataflowMap])

  // Get selected component threat
  const selectedComponentThreat = useMemo(() => {
    if (!selectedThreatId) return null
    return filteredComponentThreats.find((ct) => ct.id === selectedThreatId) || null
  }, [filteredComponentThreats, selectedThreatId])

  // Get backend info for selected component (for AddThreatDialog)
  const selectedBackendInfo = useMemo(() => {
    if (!selectedComponentId) return null

    // Check if it's a data flow (edge)
    const isDataflow = dataFlows.some(df => df.id === selectedComponentId)

    if (isDataflow) {
      const edge = dataFlows.find(df => df.id === selectedComponentId)
      // Get dataflow backend ID from edge metadata or edgeDataflowMap
      const dataflowId = (edge?.data?.dataflowId as number | undefined)
        ?? threatData?.edgeDataflowMap?.[selectedComponentId]?.dataflowId
      if (dataflowId) {
        return {
          backendId: dataflowId,
          type: 'dataflow' as const,
          name: edge?.data?.label || `${edge?.source} → ${edge?.target}` || 'Data Flow',
        }
      }
      return null
    }

    // Check if it's an analysis-only component (ID starts with "analysis-")
    if (selectedComponentId.startsWith('analysis-')) {
      const backendId = parseInt(selectedComponentId.replace('analysis-', ''), 10)
      const analysisComp = analysisComponents.find(c => c.id === backendId)
      if (analysisComp) {
        return {
          backendId,
          type: 'component' as const,
          name: analysisComp.name,
        }
      }
      return null
    }

    // For canvas components, use the nodeComponentMap
    const mapping = nodeComponentMap[selectedComponentId]
    if (mapping) {
      const node = aggregatedCanvasData.nodes.find(n => n.id === selectedComponentId)
      const nodeName = node ? String(node.data.label) : selectedComponentId
      return {
        backendId: mapping.componentId,
        type: 'component' as const,
        name: nodeName,
      }
    }

    return null
  }, [selectedComponentId, dataFlows, threatData?.edgeDataflowMap, nodeComponentMap, aggregatedCanvasData.nodes, analysisComponents])

  // Get backend info for selected threat (for AddCountermeasureDialog)
  const selectedThreatBackendInfo = useMemo(() => {
    if (!selectedComponentThreat) return null
    if (!selectedComponentThreat.backendThreatId) return null

    // Parse threatLibraryId from threatId (format: "lib-{id}")
    const parsedId = selectedComponentThreat.threatId.startsWith('lib-')
      ? parseInt(selectedComponentThreat.threatId.slice(4), 10)
      : null
    const threatLibraryId = parsedId != null && !Number.isNaN(parsedId) ? parsedId : null

    return {
      backendId: selectedComponentThreat.backendThreatId,
      type: selectedComponentThreat.threatType || 'component',
      name: selectedComponentThreat.threatName || 'Unknown Threat',
      threatLibraryId,
    }
  }, [selectedComponentThreat])

  // Inline name editing handlers
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

  const canWrite = threatModel.canWrite === true

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
            {isEditingName && canWrite ? (
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
                disabled={!canWrite}
                className={cn(
                  'font-semibold truncate flex items-center gap-1',
                  canWrite && 'hover:text-primary group cursor-pointer'
                )}
                title={canWrite ? 'Click to rename' : 'Read-only access'}
              >
                {threatModel.name}
                {canWrite && (
                  <Pencil className="h-3 w-3 opacity-0 group-hover:opacity-100 touch:opacity-100 transition-opacity text-muted-foreground" />
                )}
              </button>
            )}
            <span className="text-muted-foreground">/</span>
            <span className="text-sm text-muted-foreground">Workspace</span>
          </div>

          {/* Right: Actions */}
          <div className="flex items-center gap-3">
            {canWrite && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 px-2 text-xs gap-1"
                onClick={() => setShareLinkDialogOpen(true)}
              >
                <Share2 className="h-3 w-3" />
                <span className="hidden sm:inline">Share</span>
              </Button>
            )}

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
                  onClick={() => id && exportTmLibrary(id)}
                  className="text-xs"
                >
                  TM-Library (JSON)
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => id && exportCycloneDx(id)}
                  className="text-xs"
                >
                  CycloneDX 2.0 BOM
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            {canWrite && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 px-2 text-xs gap-1 text-red-600 hover:text-red-700 hover:bg-red-50"
                onClick={() => setDeleteDialogOpen(true)}
              >
                <Trash2 className="h-3 w-3" />
                <span className="hidden sm:inline">Delete</span>
              </Button>
            )}

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
            threatModelId={id!}
            diagrams={diagrams}
            progressChecklist={progressChecklist}
            completionStatus={completionStatus}
            summaries={summaries}
            selectedDiagramId={selectedDiagramId}
            referenceImages={referenceImages}
            isCreatingDiagram={createDiagramMutation.isPending}
            isUploadingImage={uploadImageMutation.isPending}
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
            onManageSystems={() => setManageSystemsModalOpen(true)}
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
                  {diagrams.length > 0 && (
                    <div className="flex items-center gap-2">
                      <select
                        value={selectedDiagramId || ''}
                        onChange={(e) => setSelectedDiagramId(e.target.value || null)}
                        className="text-sm border rounded-md px-2 py-1 bg-background"
                      >
                        <option value="">All</option>
                        {diagrams.map((d) => (
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
                          const diagramId = selectedDiagramId || diagrams.find((d) => d.isPrimary)?.id || diagrams[0].id
                          navigate(`/threat-models/${id}/diagrams/${diagramId}`)
                        }}
                      >
                        DFD
                      </Button>
                    </div>
                  )}
                  {/* Zone Protections Button */}
                  {canWrite && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setZoneProtectionsDialogOpen(true)}
                      className="gap-1"
                    >
                      <Shield className="h-4 w-4" />
                      Zone Protections
                    </Button>
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
                    canvasData={aggregatedCanvasData}
                    analyzableComponents={analyzableComponents}
                    trustZones={trustZones}
                    dataFlows={dataFlows}
                    componentThreats={filteredComponentThreats}
                    selectedComponentId={selectedComponentId}
                    selectedThreatId={selectedThreatId}
                    selectedComponentThreat={selectedComponentThreat}
                    onSelectComponent={(id: string) => {
                      if (id !== selectedComponentId) {
                        setSelectedThreatId(null)
                      }
                      setSelectedComponentId(id)
                    }}
                    onSelectThreat={setSelectedThreatId}
                    onCountermeasureStatusChange={updateCountermeasureStatus}
                    onAssignOwner={assignOwner}
                    onAddComponent={() => setAddComponentDialogOpen(true)}
                    onAddCustomThreat={() => setAddThreatDialogOpen(true)}
                    onUpdateTriageStatus={(threatId, status, rationale) => {
                      if (selectedComponentId) {
                        updateTriageStatus(threatId, selectedComponentId, status, rationale)
                      }
                    }}
                    onAddCustomCountermeasure={() => setAddCountermeasureDialogOpen(true)}
                    onCountermeasurePriorityChange={updateCountermeasurePriority}
                    onCountermeasureDueDateChange={updateCountermeasureDueDate}
                    onCountermeasureExternalTicketChange={updateCountermeasureExternalTicket}
                    onRevertCountermeasure={revertInheritedCountermeasure}
                    onReorderThreats={reorderThreats}
                    onReorderCountermeasures={reorderCountermeasures}
                    isSecurityTeam={isSecurityTeam}
                  />
                ) : (
                  <TableView
                    canvasData={aggregatedCanvasData}
                    componentThreats={filteredComponentThreats}
                    onCountermeasureStatusChange={updateCountermeasureStatus}
                    onSelectThreat={(componentId, threatId) => {
                      setSelectedComponentId(componentId)
                      setSelectedThreatId(threatId)
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
            componentThreats={componentThreats}
            riskScoringMethod={threatModel.riskScoringMethod ?? 'tm_library'}
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
      />

      <ManageSystemsModal
        open={manageSystemsModalOpen}
        onOpenChange={setManageSystemsModalOpen}
        connectedSystems={linkedSystems}
        availableSystems={systems}
        onAdd={(systemId) => addSystemMutation.mutate({ threatModelId: id!, systemId: Number(systemId) })}
        onRemove={(systemId) => removeSystemMutation.mutate({ threatModelId: id!, systemId: Number(systemId) })}
      />

      <ManageThreatModelsModal
        open={manageThreatModelsModalOpen}
        onOpenChange={setManageThreatModelsModalOpen}
        connectedModels={referencedModels}
        availableModels={allThreatModels.filter((m) => String(m.id) !== id)}
        currentModelId={id!}
        onAdd={(modelId) => addReferencedModelMutation.mutate({ threatModelId: id!, targetModelId: Number(modelId) })}
        onRemove={(modelId) => removeReferencedModelMutation.mutate({ threatModelId: id!, targetModelId: Number(modelId) })}
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
      {selectedBackendInfo && (
        <AddThreatDialog
          open={addThreatDialogOpen}
          onOpenChange={setAddThreatDialogOpen}
          targetId={selectedBackendInfo.backendId}
          targetType={selectedBackendInfo.type}
          targetName={selectedBackendInfo.name}
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
          threatType={selectedThreatBackendInfo.type as 'component' | 'dataflow'}
          threatName={selectedThreatBackendInfo.name}
          threatLibraryId={selectedThreatBackendInfo.threatLibraryId}
          threatModelId={id}
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
        onSuccess={() => {
          refetchThreats()
        }}
      />

      {/* Zone Protections Dialog */}
      <ReviewZoneProtectionsDialog
        open={zoneProtectionsDialogOpen}
        onOpenChange={setZoneProtectionsDialogOpen}
        threatModelId={id!}
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
