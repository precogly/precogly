import { useCallback, useMemo, useRef, useState } from 'react'
import { Outlet, useNavigate } from 'react-router-dom'
import type { NodeChange, EdgeChange } from '@xyflow/react'
import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'
import type { DFDNotationStyle } from '@/features/dfd-editor/types/notation'
import type { ExportImageOptions } from '@/features/dfd-editor/lib/export-diagram-image'
import { useGuestDiagramState } from './hooks/useGuestDiagramState'
import { useGuestThreats } from './hooks/useGuestThreats'
import { useGuestCountermeasures } from './hooks/useGuestCountermeasures'
import { useGuestSystemContext } from './hooks/useGuestSystemContext'
import { useFileHandle } from './hooks/useFileHandle'
import { GuestEditorProvider } from './context/GuestEditorContext'
import { GuestEditorHeader } from './components/GuestEditorHeader'
import type { GuestSystemContext } from './types'

export interface GuestDiagramOutletContext {
  title: string
  nodes: DiagramNode[]
  edges: DiagramEdge[]
  setNodes: React.Dispatch<React.SetStateAction<DiagramNode[]>>
  setEdges: React.Dispatch<React.SetStateAction<DiagramEdge[]>>
  onNodesChange: (changes: NodeChange<DiagramNode>[]) => void
  onEdgesChange: (changes: EdgeChange<DiagramEdge>[]) => void
  undo: () => void
  canUndo: boolean
  redo: () => void
  canRedo: boolean
  notationStyle: DFDNotationStyle
  setNotationStyle: (notation: DFDNotationStyle) => void
  exportImageRef: React.MutableRefObject<((format: 'png' | 'svg', options?: ExportImageOptions) => void | Promise<void>) | null>
  captureImageRef: React.MutableRefObject<(() => Promise<Uint8Array | null>) | null>
  onCacheImage: (image: Uint8Array | null) => void
  showComponentPanel: boolean
  setShowComponentPanel: React.Dispatch<React.SetStateAction<boolean>>
  exportDialogOpen: boolean
  setExportDialogOpen: React.Dispatch<React.SetStateAction<boolean>>
}

export function GuestLayout() {
  const navigate = useNavigate()
  const diagramState = useGuestDiagramState()
  const threatOps = useGuestThreats()
  const countermeasureOps = useGuestCountermeasures()
  const systemContextOps = useGuestSystemContext()
  const [notationStyle, setNotationStyle] = useState<DFDNotationStyle>('yourdon')
  const [showComponentPanel, setShowComponentPanel] = useState(true)
  const [exportDialogOpen, setExportDialogOpen] = useState(false)
  const fileHandleState = useFileHandle()
  const exportImageRef = useRef<((format: 'png' | 'svg', options?: ExportImageOptions) => void | Promise<void>) | null>(null)
  const captureImageRef = useRef<(() => Promise<Uint8Array | null>) | null>(null)
  const [cachedDiagramImage, setCachedDiagramImage] = useState<Uint8Array | null>(null)

  // Wrap removeThreat to cascade-delete countermeasures
  const removeThreatWithCascade = useCallback(
    (threatId: string) => {
      threatOps.removeThreat(threatId)
      countermeasureOps.removeCountermeasuresForThreat(threatId)
    },
    [threatOps.removeThreat, countermeasureOps.removeCountermeasuresForThreat]
  )

  const contextValue = useMemo(
    () => ({
      // Diagram data (read-only)
      nodes: diagramState.nodes,
      edges: diagramState.edges,
      title: diagramState.title,

      // Threat operations (with cascade delete)
      addThreat: threatOps.addThreat,
      updateThreat: threatOps.updateThreat,
      removeThreat: removeThreatWithCascade,
      getThreatsForTarget: threatOps.getThreatsForTarget,
      getThreatCount: threatOps.getThreatCount,
      getAllThreats: threatOps.getAllThreats,
      loadThreats: threatOps.loadThreats,

      // Countermeasure operations
      addCountermeasure: countermeasureOps.addCountermeasure,
      updateCountermeasure: countermeasureOps.updateCountermeasure,
      removeCountermeasure: countermeasureOps.removeCountermeasure,
      getCountermeasuresForThreat: countermeasureOps.getCountermeasuresForThreat,
      getCountermeasureCount: countermeasureOps.getCountermeasureCount,
      getAllCountermeasures: countermeasureOps.getAllCountermeasures,
      loadCountermeasures: countermeasureOps.loadCountermeasures,

      // System Context state
      session: systemContextOps.session,
      systemInfo: systemContextOps.systemInfo,
      dataAssets: systemContextOps.dataAssets,
      assumptions: systemContextOps.assumptions,
      outOfScopeItems: systemContextOps.outOfScopeItems,

      // System Context operations
      updateSession: systemContextOps.updateSession,
      updateSystemInfo: systemContextOps.updateSystemInfo,
      addDataAsset: systemContextOps.addDataAsset,
      updateDataAsset: systemContextOps.updateDataAsset,
      removeDataAsset: systemContextOps.removeDataAsset,
      addAssumption: systemContextOps.addAssumption,
      updateAssumption: systemContextOps.updateAssumption,
      removeAssumption: systemContextOps.removeAssumption,
      addOutOfScopeItem: systemContextOps.addOutOfScopeItem,
      updateOutOfScopeItem: systemContextOps.updateOutOfScopeItem,
      removeOutOfScopeItem: systemContextOps.removeOutOfScopeItem,
      loadSystemContext: systemContextOps.loadSystemContext,
      getSystemContext: systemContextOps.getSystemContext,
    }),
    [
      diagramState.nodes,
      diagramState.edges,
      diagramState.title,
      threatOps.addThreat,
      threatOps.updateThreat,
      removeThreatWithCascade,
      threatOps.getThreatsForTarget,
      threatOps.getThreatCount,
      threatOps.getAllThreats,
      threatOps.loadThreats,
      countermeasureOps.addCountermeasure,
      countermeasureOps.updateCountermeasure,
      countermeasureOps.removeCountermeasure,
      countermeasureOps.getCountermeasuresForThreat,
      countermeasureOps.getCountermeasureCount,
      countermeasureOps.getAllCountermeasures,
      countermeasureOps.loadCountermeasures,
      systemContextOps.session,
      systemContextOps.systemInfo,
      systemContextOps.dataAssets,
      systemContextOps.assumptions,
      systemContextOps.outOfScopeItems,
      systemContextOps.updateSession,
      systemContextOps.updateSystemInfo,
      systemContextOps.addDataAsset,
      systemContextOps.updateDataAsset,
      systemContextOps.removeDataAsset,
      systemContextOps.addAssumption,
      systemContextOps.updateAssumption,
      systemContextOps.removeAssumption,
      systemContextOps.addOutOfScopeItem,
      systemContextOps.updateOutOfScopeItem,
      systemContextOps.removeOutOfScopeItem,
      systemContextOps.loadSystemContext,
      systemContextOps.getSystemContext,
    ]
  )

  const handleCacheImage = useCallback((image: Uint8Array | null) => {
    setCachedDiagramImage(image)
  }, [])

  const outletContext: GuestDiagramOutletContext = useMemo(
    () => ({
      title: diagramState.title,
      nodes: diagramState.nodes,
      edges: diagramState.edges,
      setNodes: diagramState.setNodes,
      setEdges: diagramState.setEdges,
      onNodesChange: diagramState.onNodesChange,
      onEdgesChange: diagramState.onEdgesChange,
      undo: diagramState.undo,
      canUndo: diagramState.canUndo,
      redo: diagramState.redo,
      canRedo: diagramState.canRedo,
      notationStyle,
      setNotationStyle,
      exportImageRef,
      captureImageRef,
      onCacheImage: handleCacheImage,
      showComponentPanel,
      setShowComponentPanel,
      exportDialogOpen,
      setExportDialogOpen,
    }),
    [
      diagramState.title,
      diagramState.nodes,
      diagramState.edges,
      diagramState.setNodes,
      diagramState.setEdges,
      diagramState.onNodesChange,
      diagramState.onEdgesChange,
      diagramState.undo,
      diagramState.canUndo,
      diagramState.redo,
      diagramState.canRedo,
      notationStyle,
      handleCacheImage,
      showComponentPanel,
      exportDialogOpen,
    ]
  )

  const handleLoadFromFile = useCallback(
    (data: { title: string; nodes: DiagramNode[]; edges: DiagramEdge[]; notationStyle?: DFDNotationStyle; systemContext?: GuestSystemContext }) => {
      diagramState.loadFromFile(data)
      setNotationStyle(data.notationStyle ?? 'yourdon')
      setCachedDiagramImage(null)
      if (data.systemContext) {
        systemContextOps.loadSystemContext(data.systemContext)
      }
    },
    [diagramState.loadFromFile, systemContextOps.loadSystemContext]
  )

  const handleAnalyzeThreats = useCallback(async () => {
    const image = await captureImageRef.current?.() ?? null
    setCachedDiagramImage(image)
    navigate('/guest/threats')
  }, [navigate])

  return (
    <GuestEditorProvider value={contextValue}>
      <div className="flex flex-col h-screen">
        <GuestEditorHeader
          title={diagramState.title}
          onTitleChange={diagramState.setTitle}
          hasUnsavedChanges={diagramState.hasUnsavedChanges}
          onMarkSaved={diagramState.markSaved}
          onLoadFromFile={handleLoadFromFile}
          notationStyle={notationStyle}
          onNotationChange={setNotationStyle}
          onCaptureImage={async () => (await captureImageRef.current?.()) ?? cachedDiagramImage}
          onAnalyzeThreats={handleAnalyzeThreats}
          onOpenExportDialog={() => setExportDialogOpen(true)}
          onUndo={diagramState.undo}
          onRedo={diagramState.redo}
          canUndo={diagramState.canUndo}
          canRedo={diagramState.canRedo}
          showComponentPanel={showComponentPanel}
          onToggleComponentPanel={() => setShowComponentPanel((prev) => !prev)}
          fileHandle={fileHandleState.fileHandle}
          fileName={fileHandleState.fileName}
          onFileHandleChange={fileHandleState.updateHandle}
          onFileHandleClear={fileHandleState.clearHandle}
        />
        <Outlet context={outletContext} />
      </div>
    </GuestEditorProvider>
  )
}
