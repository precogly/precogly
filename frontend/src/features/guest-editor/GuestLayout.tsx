import { useCallback, useMemo, useRef, useState } from 'react'
import { Outlet, useNavigate } from 'react-router-dom'
import type { NodeChange, EdgeChange } from '@xyflow/react'
import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'
import type { DFDNotationStyle } from '@/features/dfd-editor/types/notation'
import type { ExportImageOptions } from '@/features/dfd-editor/lib/export-diagram-image'
import { useGuestDiagramState } from './hooks/useGuestDiagramState'
import { useGuestModel } from './hooks/useGuestModel'
import { useGuestSystemContext } from './hooks/useGuestSystemContext'
import { useFileHandle } from './hooks/useFileHandle'
import { GuestEditorProvider, type GuestEditorContextType } from './context/GuestEditorContext'
import { GuestEditorHeader } from './components/GuestEditorHeader'
import { GuestFileNotices } from './components/GuestFileNotices'
import type { DeserializedFile } from './lib/cyclonedx-guest'

/** The notation the canvas draws when the file does not say (the file keeps saying nothing). */
export const DEFAULT_GUEST_NOTATION: DFDNotationStyle = 'yourdon'

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
  const model = useGuestModel()
  const systemContextOps = useGuestSystemContext()
  // Undefined means the file did not record a notation; the canvas draws the default.
  const [notationStyle, setNotationStyle] = useState<DFDNotationStyle | undefined>(undefined)
  const [showComponentPanel, setShowComponentPanel] = useState(true)
  const [exportDialogOpen, setExportDialogOpen] = useState(false)
  const [fileWarnings, setFileWarnings] = useState<string[]>([])
  const [hiddenBlueprintCount, setHiddenBlueprintCount] = useState(0)
  const [hiddenElementCount, setHiddenElementCount] = useState(0)
  const fileHandleState = useFileHandle()
  const exportImageRef = useRef<((format: 'png' | 'svg', options?: ExportImageOptions) => void | Promise<void>) | null>(null)
  const captureImageRef = useRef<(() => Promise<Uint8Array | null>) | null>(null)
  const [cachedDiagramImage, setCachedDiagramImage] = useState<Uint8Array | null>(null)

  const contextValue: GuestEditorContextType = useMemo(
    () => ({
      ...model,
      nodes: diagramState.nodes,
      edges: diagramState.edges,
      title: diagramState.title,
      hiddenBlueprintCount,
      hiddenElementCount,
      session: systemContextOps.session,
      systemInfo: systemContextOps.systemInfo,
      dataAssets: systemContextOps.dataAssets,
      assumptions: systemContextOps.assumptions,
      outOfScopeItems: systemContextOps.outOfScopeItems,
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
    [model, diagramState.nodes, diagramState.edges, diagramState.title, hiddenBlueprintCount, hiddenElementCount, systemContextOps]
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
      notationStyle: notationStyle ?? DEFAULT_GUEST_NOTATION,
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
    (loaded: DeserializedFile) => {
      diagramState.loadFromFile({ title: loaded.title, nodes: loaded.nodes, edges: loaded.edges })
      setNotationStyle(loaded.notationStyle)
      setCachedDiagramImage(null)
      systemContextOps.loadSystemContext(loaded.systemContext)
      model.loadModel({
        threats: loaded.threats,
        countermeasures: loaded.countermeasures,
        documentState: loaded.documentState,
      })
      setFileWarnings(loaded.warnings)
      setHiddenBlueprintCount(loaded.hiddenBlueprintCount)
      setHiddenElementCount(loaded.hiddenElementCount)
    },
    [diagramState, systemContextOps, model]
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
        <GuestFileNotices
          warnings={fileWarnings}
          onDismissWarnings={() => setFileWarnings([])}
          hiddenBlueprintCount={hiddenBlueprintCount}
          hiddenElementCount={hiddenElementCount}
        />
        <Outlet context={outletContext} />
      </div>
    </GuestEditorProvider>
  )
}
