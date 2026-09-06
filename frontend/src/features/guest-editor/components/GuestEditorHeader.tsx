import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Download, FileText, FolderOpen, Pencil, ArrowLeft, Save, ChevronDown, ShieldAlert, Undo2, Redo2, HelpCircle, ImageDown, PanelLeft, MoreHorizontal } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import type { DFDNotationStyle } from '@/features/dfd-editor/types/notation'
import { useGuestEditor } from '../context/GuestEditorContext'
import { serializeGuestToCycloneDx, deserializeCycloneDxToGuest } from '../lib/cyclonedx-guest'
import {
  supportsFileSystemAccess,
  pickFileToSave,
  pickFileToOpen,
  writeToHandle,
  downloadAsFallback,
  openFileViaInput,
} from '../lib/file-system-access'
import { exportGuestWordDoc } from '../lib/guestWordExport'
import { GuestSystemContextModal } from './GuestSystemContextModal'

function titleToFilename(title: string): string {
  return title.replace(/[^a-zA-Z0-9-_ ]/g, '').replace(/\s+/g, '-').toLowerCase() || 'diagram'
}

interface GuestEditorHeaderProps {
  title: string
  onTitleChange: (title: string) => void
  hasUnsavedChanges: boolean
  onMarkSaved: () => void
  onLoadFromFile: (data: { title: string; nodes: import('@/features/dfd-editor/types').DiagramNode[]; edges: import('@/features/dfd-editor/types').DiagramEdge[]; notationStyle?: DFDNotationStyle; systemContext?: import('../types').GuestSystemContext }) => void
  notationStyle?: DFDNotationStyle
  onNotationChange?: (notation: DFDNotationStyle) => void
  onCaptureImage: () => Promise<Uint8Array | null>
  onAnalyzeThreats: () => void
  onOpenExportDialog?: () => void
  onUndo?: () => void
  onRedo?: () => void
  canUndo?: boolean
  canRedo?: boolean
  showComponentPanel?: boolean
  onToggleComponentPanel?: () => void
  fileHandle: FileSystemFileHandle | null
  fileName: string | null
  onFileHandleChange: (handle: FileSystemFileHandle) => void
  onFileHandleClear: () => void
}

export function GuestEditorHeader({
  title,
  onTitleChange,
  hasUnsavedChanges,
  onMarkSaved,
  onLoadFromFile,
  notationStyle,
  onNotationChange,
  onCaptureImage,
  onAnalyzeThreats,
  onOpenExportDialog,
  onUndo,
  onRedo,
  canUndo = false,
  canRedo = false,
  showComponentPanel = false,
  onToggleComponentPanel,
  fileHandle,
  fileName,
  onFileHandleChange,
  onFileHandleClear,
}: GuestEditorHeaderProps) {
  const navigate = useNavigate()
  const location = useLocation()
  const guestEditor = useGuestEditor()
  const isOnThreatsView = location.pathname === '/guest/threats'
  const [isEditingTitle, setIsEditingTitle] = useState(false)
  const [titleValue, setTitleValue] = useState('')
  const titleInputRef = useRef<HTMLInputElement>(null)
  const [shortcutsOpen, setShortcutsOpen] = useState(false)

  // System context modal state
  const [showSystemContextModal, setShowSystemContextModal] = useState(false)

  // Save dialog state (fallback for browsers without File System Access API)
  const [showSaveDialog, setShowSaveDialog] = useState(false)
  const [saveFilename, setSaveFilename] = useState('')
  const filenameInputRef = useRef<HTMLInputElement>(null)

  // Keyboard shortcut help (? key)
  useEffect(() => {
    const handleShortcutHelp = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) return
      if (event.key === '?') {
        event.preventDefault()
        setShortcutsOpen(true)
      }
    }
    window.addEventListener('keydown', handleShortcutHelp)
    return () => window.removeEventListener('keydown', handleShortcutHelp)
  }, [])

  const handleTitleClick = useCallback(() => {
    setTitleValue(title)
    setIsEditingTitle(true)
    setTimeout(() => titleInputRef.current?.select(), 0)
  }, [title])

  const handleTitleSave = useCallback(() => {
    const trimmedTitle = titleValue.trim()
    if (trimmedTitle && trimmedTitle !== title) {
      onTitleChange(trimmedTitle)
    }
    setIsEditingTitle(false)
  }, [titleValue, title, onTitleChange])

  const handleTitleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') {
        handleTitleSave()
      } else if (e.key === 'Escape') {
        setIsEditingTitle(false)
      }
    },
    [handleTitleSave]
  )

  // --- Serialize current state to CycloneDX JSON ---
  const serializeContent = useCallback(() => {
    if (!guestEditor) return ''
    const threats = guestEditor.getAllThreats()
    const countermeasures = guestEditor.getAllCountermeasures()
    const systemContext = guestEditor.getSystemContext()
    return serializeGuestToCycloneDx(
      title,
      guestEditor.nodes,
      guestEditor.edges,
      threats,
      countermeasures,
      notationStyle,
      systemContext
    )
  }, [title, guestEditor, notationStyle])

  // --- Save handler ---
  const handleSave = useCallback(async () => {
    if (!guestEditor) return
    const content = serializeContent()

    if (supportsFileSystemAccess()) {
      if (fileHandle) {
        // Silent save to existing handle
        try {
          await writeToHandle(fileHandle, content)
          onMarkSaved()
        } catch {
          // Handle might be stale (file deleted externally) — clear and re-prompt
          onFileHandleClear()
          try {
            const newHandle = await pickFileToSave(`${titleToFilename(title)}.cdx.json`)
            await writeToHandle(newHandle, content)
            onFileHandleChange(newHandle)
            onMarkSaved()
          } catch (innerError) {
            // User cancelled — silently ignore AbortError
            if (innerError instanceof DOMException && innerError.name === 'AbortError') return
          }
        }
      } else {
        // No handle yet — prompt for location
        try {
          const newHandle = await pickFileToSave(`${titleToFilename(title)}.cdx.json`)
          await writeToHandle(newHandle, content)
          onFileHandleChange(newHandle)
          onMarkSaved()
        } catch (error) {
          if (error instanceof DOMException && error.name === 'AbortError') return
        }
      }
    } else {
      // Fallback: show filename dialog
      setSaveFilename(titleToFilename(title))
      setShowSaveDialog(true)
      setTimeout(() => filenameInputRef.current?.select(), 0)
    }
  }, [guestEditor, serializeContent, fileHandle, title, onMarkSaved, onFileHandleChange, onFileHandleClear])

  // --- Save As handler (always prompts for new location) ---
  const handleSaveAs = useCallback(async () => {
    if (!guestEditor) return
    const content = serializeContent()

    if (supportsFileSystemAccess()) {
      try {
        const newHandle = await pickFileToSave(`${titleToFilename(title)}.cdx.json`)
        await writeToHandle(newHandle, content)
        onFileHandleChange(newHandle)
        onMarkSaved()
      } catch (error) {
        if (error instanceof DOMException && error.name === 'AbortError') return
      }
    } else {
      setSaveFilename(titleToFilename(title))
      setShowSaveDialog(true)
      setTimeout(() => filenameInputRef.current?.select(), 0)
    }
  }, [guestEditor, serializeContent, title, onMarkSaved, onFileHandleChange])

  // --- Fallback save dialog confirm ---
  const handleConfirmSave = useCallback(() => {
    const content = serializeContent()
    const filename = saveFilename.trim() || titleToFilename(title)
    downloadAsFallback(filename, content)
    onMarkSaved()
    setShowSaveDialog(false)
  }, [saveFilename, title, serializeContent, onMarkSaved])

  // --- Open handler ---
  const handleOpen = useCallback(async () => {
    try {
      let content: string
      let handle: FileSystemFileHandle | null = null

      if (supportsFileSystemAccess()) {
        const result = await pickFileToOpen()
        content = result.content
        handle = result.handle
      } else {
        content = await openFileViaInput()
      }

      const data = deserializeCycloneDxToGuest(content)
      onLoadFromFile({
        title: data.title,
        nodes: data.nodes,
        edges: data.edges,
        notationStyle: data.notationStyle,
        systemContext: data.systemContext,
      })
      if (guestEditor) {
        guestEditor.loadThreats(data.threats)
        guestEditor.loadCountermeasures(data.countermeasures)
        if (data.systemContext) {
          guestEditor.loadSystemContext(data.systemContext)
        }
      }

      if (handle) {
        onFileHandleChange(handle)
      } else {
        onFileHandleClear()
      }
    } catch (error) {
      // User cancelled or AbortError — silently ignore
      if (error instanceof DOMException && error.name === 'AbortError') return
      // Show error for invalid files
      if (error instanceof Error && error.message) {
        alert(error.message)
      }
    }
  }, [onLoadFromFile, guestEditor, onFileHandleChange, onFileHandleClear])

  // --- Ctrl+S / Cmd+S keyboard shortcut ---
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault()
        handleSave()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [handleSave])

  const handleDownloadReport = useCallback(async () => {
    if (!guestEditor) return
    // onCaptureImage tries live canvas capture first, falls back to cached image
    const diagramImage = await onCaptureImage() ?? undefined
    await exportGuestWordDoc({
      title,
      nodes: guestEditor.nodes,
      edges: guestEditor.edges,
      threats: guestEditor.getAllThreats(),
      countermeasures: guestEditor.getAllCountermeasures(),
      diagramImage,
      systemContext: guestEditor.getSystemContext(),
    })
  }, [title, guestEditor, onCaptureImage])

  // Determine save button tooltip
  const saveTooltip = fileHandle && fileName
    ? `Save to ${fileName}`
    : 'Save as CycloneDX JSON'

  return (
    <>
      <TooltipProvider delayDuration={300}>
        <div className="flex items-center gap-2 px-4 py-2 border-b bg-background min-h-[48px]">
          {/* Sidebar toggle */}
          {onToggleComponentPanel && (
            <>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className={cn('gap-1', showComponentPanel && 'bg-muted')}
                    onClick={onToggleComponentPanel}
                  >
                    <PanelLeft className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="bottom">
                  {showComponentPanel ? 'Hide' : 'Show'} component panel
                </TooltipContent>
              </Tooltip>
              <Separator orientation="vertical" className="h-6" />
            </>
          )}

          <button
            onClick={() => {
              if (!hasUnsavedChanges || window.confirm('Changes that you made may not be saved.')) {
                navigate('/')
              }
            }}
            className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground text-sm"
          >
            <ArrowLeft className="h-4 w-4" />
            <span className="text-xs bg-amber-100 text-amber-800 px-2 py-0.5 rounded-full">Guest</span>
          </button>
          <div className="mr-2 min-w-0 max-w-[240px] shrink">
            {isEditingTitle ? (
              <input
                ref={titleInputRef}
                type="text"
                value={titleValue}
                onChange={(e) => setTitleValue(e.target.value)}
                onBlur={handleTitleSave}
                onKeyDown={handleTitleKeyDown}
                className="font-semibold bg-transparent border-b-2 border-primary outline-none px-0 py-0 min-w-[200px]"
                autoFocus
              />
            ) : (
              <button
                onClick={handleTitleClick}
                className="flex items-center gap-2 group text-left"
              >
                <h1 className="font-semibold truncate">{title}</h1>
                <Pencil className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
              </button>
            )}
            <p className="text-xs text-muted-foreground truncate">
              {fileName ? fileName : 'Data Flow Diagram'}
            </p>
          </div>
          {hasUnsavedChanges && (
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <div className="h-2 w-2 rounded-full bg-yellow-500" />
              <span>Unsaved</span>
            </div>
          )}
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="sm" className="bg-teal-50 text-teal-700 border-teal-200 hover:bg-teal-100" onClick={() => setShowSystemContextModal(true)}>
                <Pencil className="h-3.5 w-3.5 mr-1.5" />
                Add / Edit Context
              </Button>
            </TooltipTrigger>
            <TooltipContent>Define system context, data assets, and assumptions</TooltipContent>
          </Tooltip>

          {/* Canvas tools (from toolbar) */}
          {(onUndo || onRedo) && (
            <div className="hidden xl:flex items-center gap-0.5">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-8 w-8" onClick={onUndo} disabled={!canUndo} aria-label="Undo">
                    <Undo2 className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="bottom">Undo (Ctrl/Cmd + Z)</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-8 w-8" onClick={onRedo} disabled={!canRedo} aria-label="Redo">
                    <Redo2 className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="bottom">Redo (Ctrl/Cmd + Shift + Z)</TooltipContent>
              </Tooltip>
            </div>
          )}

          {onNotationChange && notationStyle && (
            <div className="hidden xl:block">
              <Select
                value={notationStyle}
                onValueChange={(value) => onNotationChange(value as DFDNotationStyle)}
              >
                <SelectTrigger className="h-8 w-[140px] text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="dfd3">DFD3</SelectItem>
                  <SelectItem value="yourdon">Yourdon</SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}

          <div className="hidden xl:block">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  aria-label="Keyboard shortcuts"
                  onClick={() => setShortcutsOpen(true)}
                >
                  <HelpCircle className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="bottom">Keyboard shortcuts (?)</TooltipContent>
            </Tooltip>
          </div>

          {onOpenExportDialog && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="gap-2"
                  onClick={onOpenExportDialog}
                >
                  <ImageDown className="h-4 w-4" />
                  <span className="hidden xl:inline">Export Image</span>
                </Button>
              </TooltipTrigger>
              <TooltipContent side="bottom">Download diagram as PNG or SVG</TooltipContent>
            </Tooltip>
          )}

          {/* Overflow menu for narrow viewports */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="xl:hidden h-8 w-8" aria-label="More options">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              {(onUndo || onRedo) && (
                <>
                  <DropdownMenuItem onClick={onUndo} disabled={!canUndo}>
                    <Undo2 className="h-4 w-4 mr-2" />
                    Undo
                    <DropdownMenuShortcut>⌘Z</DropdownMenuShortcut>
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={onRedo} disabled={!canRedo}>
                    <Redo2 className="h-4 w-4 mr-2" />
                    Redo
                    <DropdownMenuShortcut>⇧⌘Z</DropdownMenuShortcut>
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                </>
              )}
              {onNotationChange && notationStyle && (
                <>
                  <DropdownMenuLabel className="text-xs text-muted-foreground">Notation</DropdownMenuLabel>
                  <DropdownMenuRadioGroup value={notationStyle} onValueChange={(value) => onNotationChange(value as DFDNotationStyle)}>
                    <DropdownMenuRadioItem value="dfd3">DFD3</DropdownMenuRadioItem>
                    <DropdownMenuRadioItem value="yourdon">Yourdon</DropdownMenuRadioItem>
                  </DropdownMenuRadioGroup>
                  <DropdownMenuSeparator />
                </>
              )}
              <DropdownMenuItem onClick={() => setShortcutsOpen(true)}>
                <HelpCircle className="h-4 w-4 mr-2" />
                Keyboard shortcuts
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Right-aligned items */}
          <div className="flex items-center gap-2 ml-auto shrink-0">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="sm" onClick={handleOpen}>
                  <FolderOpen className="h-4 w-4 mr-2" />
                  Open
                </Button>
              </TooltipTrigger>
              <TooltipContent>Open a CycloneDX JSON file</TooltipContent>
            </Tooltip>

            {/* Save button with Save As dropdown */}
            <div className="flex items-center">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleSave}
                    className="rounded-r-none"
                  >
                    <Save className="h-4 w-4 mr-2" />
                    Save
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{saveTooltip}</TooltipContent>
              </Tooltip>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="rounded-l-none px-1.5"
                  >
                    <ChevronDown className="h-3.5 w-3.5" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={handleSave}>
                    <Save className="h-4 w-4 mr-2" />
                    Save
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={handleSaveAs}>
                    <Download className="h-4 w-4 mr-2" />
                    Save As...
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>

            {!isOnThreatsView && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="default" size="sm" onClick={onAnalyzeThreats}>
                    <ShieldAlert className="h-4 w-4 mr-2" />
                    Analyze Threats
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Review and manage threats based on your diagram components</TooltipContent>
              </Tooltip>
            )}

            {isOnThreatsView && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="default" size="sm" onClick={handleDownloadReport}>
                    <FileText className="h-4 w-4 mr-2" />
                    Report
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Download threat model report as Word document</TooltipContent>
              </Tooltip>
            )}
          </div>
        </div>
      </TooltipProvider>

      {/* Keyboard Shortcuts Dialog */}
      <Dialog open={shortcutsOpen} onOpenChange={setShortcutsOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Keyboard shortcuts</DialogTitle>
            <DialogDescription>Shortcuts are active when the canvas is focused and a form field is not being edited.</DialogDescription>
          </DialogHeader>
          <div className="divide-y rounded-md border">
            {[
              ['Ctrl/Cmd + S', 'Save the diagram'],
              ['Ctrl/Cmd + Z', 'Undo the last change'],
              ['Ctrl/Cmd + Shift + Z or Ctrl/Cmd + Y', 'Redo the last undone change'],
              ['Ctrl/Cmd + A', 'Select all nodes and edges'],
              ['Ctrl/Cmd + C', 'Copy selected nodes'],
              ['Ctrl/Cmd + V', 'Paste copied nodes or clipboard text into a selected node'],
              ['Ctrl/Cmd + D', 'Duplicate selected nodes'],
              ['Delete / Backspace', 'Delete selected nodes or edges'],
              ['Escape', 'Deselect and cancel the active interaction'],
            ].map(([shortcut, description]) => (
              <div key={shortcut} className="flex items-center justify-between gap-4 px-3 py-2 text-sm">
                <kbd className="rounded border bg-muted px-2 py-1 font-mono text-xs whitespace-nowrap">{shortcut}</kbd>
                <span className="text-right text-muted-foreground">{description}</span>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>

      {/* Save filename dialog (fallback for browsers without File System Access API) */}
      <Dialog open={showSaveDialog} onOpenChange={setShowSaveDialog}>
        <DialogContent className="sm:max-w-[400px]">
          <DialogHeader>
            <DialogTitle>Save Diagram</DialogTitle>
            <DialogDescription>Choose a filename for your diagram.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="save-filename">Filename</Label>
            <div className="flex items-center gap-1">
              <Input
                ref={filenameInputRef}
                id="save-filename"
                value={saveFilename}
                onChange={(e) => setSaveFilename(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleConfirmSave()
                }}
                className="flex-1"
              />
              <span className="text-sm text-muted-foreground shrink-0">.cdx.json</span>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowSaveDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleConfirmSave}>
              <Download className="h-4 w-4 mr-2" />
              Download
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* System Context modal */}
      <GuestSystemContextModal
        open={showSystemContextModal}
        onOpenChange={setShowSystemContextModal}
      />
    </>
  )
}
