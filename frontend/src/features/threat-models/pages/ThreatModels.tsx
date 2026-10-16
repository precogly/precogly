import { useRef, useState, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Plus, Share2, ExternalLink, Trash2, Upload, FileJson, AlertCircle, CheckCircle2 } from 'lucide-react'
import { ApiError } from '@/lib/api'
import { CreateThreatModelDialog } from '@/features/threat-models/components'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { ThreatModelsTable } from '@/features/threat-models/components'
import { useThreatModels, useImportCycloneDx, type ImportCycloneDxResponse } from '@/features/threat-models/api/threat-models'
import { useSharedWithMe, useRemoveSharedWithMe } from '@/features/organization/api/organizations'

export function ThreatModels() {
  const { data: threatModels, isLoading } = useThreatModels()
  const { data: sharedModels, isLoading: isLoadingShared } = useSharedWithMe()
  const removeSharedMutation = useRemoveSharedWithMe()
  const importCycloneDxMutation = useImportCycloneDx()
  const navigate = useNavigate()

  const [importDialogOpen, setImportDialogOpen] = useState(false)
  const [importResult, setImportResult] = useState<ImportCycloneDxResponse | null>(null)
  const [importError, setImportError] = useState<string | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    })
  }

  // CycloneDX TM-BOM is the one import format (L8).
  const importMutation = importCycloneDxMutation

  const handleImportFile = useCallback((file: File) => {
    if (!file.name.endsWith('.json')) {
      setImportError('Only .json or .cdx.json files are accepted.')
      return
    }
    setImportError(null)
    setImportResult(null)
    importMutation.mutate(file, {
      onSuccess: (data) => {
        setImportResult(data)
      },
      onError: (error) => {
        if (error instanceof ApiError && error.data) {
          const data = error.data as Record<string, unknown>
          if (typeof data.detail === 'string') {
            setImportError(data.detail)
            return
          }
        }
        setImportError(error instanceof Error ? error.message : 'Import failed')
      },
    })
  }, [importMutation])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) handleImportFile(file)
  }, [handleImportFile])

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleImportFile(file)
    // Reset input so same file can be re-selected
    e.target.value = ''
  }, [handleImportFile])

  const handleNavigateToImported = () => {
    if (importResult) {
      setImportDialogOpen(false)
      navigate(`/threat-models/${importResult.threatModel.id}`)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Threat Models</h1>
          <p className="text-muted-foreground">
            View and manage your threat models.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => {
              setImportResult(null)
              setImportError(null)
              setImportDialogOpen(true)
            }}
          >
            <Upload className="mr-2 h-4 w-4" />
            Import
          </Button>
          <Button onClick={() => setCreateDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            New Threat Model
          </Button>
        </div>
      </div>

      {/* Create Dialog */}
      <CreateThreatModelDialog
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
      />

      {/* Import Dialog */}
      <Dialog open={importDialogOpen} onOpenChange={setImportDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Import Threat Model</DialogTitle>
            <DialogDescription>
              Import a threat model from a JSON file.
            </DialogDescription>
          </DialogHeader>

          {!importResult ? (
            <div className="space-y-4">
              <p className="text-xs text-muted-foreground">CycloneDX 2.0 TM-BOM (.cdx.json)</p>

              {/* Dropzone */}
              <div
                className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors cursor-pointer ${
                  isDragging ? 'border-primary bg-primary/5' : 'border-muted-foreground/25 hover:border-primary/50'
                }`}
                onDragOver={(e) => { e.preventDefault(); setIsDragging(true) }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
              >
                <FileJson className="h-10 w-10 mx-auto text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground">
                  Drop a .json or .cdx.json file here or click to browse
                </p>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,.cdx.json"
                  className="hidden"
                  onChange={handleFileChange}
                />
              </div>

              {importMutation.isPending && (
                <p className="text-sm text-muted-foreground text-center">Importing...</p>
              )}

              {importError && (
                <div className="flex items-start gap-2 p-3 rounded-md bg-destructive/10 text-destructive text-sm">
                  <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                  <span>{importError}</span>
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-start gap-2 p-3 rounded-md bg-green-50 text-green-700 text-sm">
                <CheckCircle2 className="h-4 w-4 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="font-medium">Import successful</p>
                  <p className="mt-1">Created "{importResult.threatModel.name}"</p>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 text-xs">
                {Object.entries(importResult.summary)
                  .filter(([key, val]) => key !== 'warnings' && typeof val === 'number' && val > 0)
                  .map(([key, val]) => (
                    <div key={key} className="p-2 rounded bg-muted text-center">
                      <div className="font-semibold">{val as number}</div>
                      <div className="text-muted-foreground">{key.replace(/([A-Z])/g, ' $1').trim()}</div>
                    </div>
                  ))}
              </div>

              {importResult.summary.warnings?.length > 0 && (
                <div className="p-3 rounded-md bg-yellow-50 text-yellow-700 text-xs space-y-1">
                  <p className="font-medium">Warnings:</p>
                  {importResult.summary.warnings.map((w, i) => (
                    <p key={i}>{w}</p>
                  ))}
                </div>
              )}

              <Button className="w-full" onClick={handleNavigateToImported}>
                Open Threat Model
              </Button>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Threat Models Table */}
      <Card>
        <CardHeader>
          <CardTitle>My Threat Models</CardTitle>
        </CardHeader>
        <CardContent>
          <ThreatModelsTable
            threatModels={threatModels ?? []}
            isLoading={isLoading}
          />
        </CardContent>
      </Card>

      {/* Shared with Me Section */}
      {!isLoadingShared && sharedModels && sharedModels.length > 0 && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Share2 className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Shared with Me</CardTitle>
            </div>
            <CardDescription>
              Threat models shared with you via magic links. You have read-only access.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {sharedModels.map((shared) => (
                <div
                  key={shared.id}
                  className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h4 className="font-medium truncate">{shared.threatModelName}</h4>
                    </div>
                    <div className="flex items-center gap-4 mt-1 text-sm text-muted-foreground">
                      <span>{shared.organizationName}</span>
                      {shared.sharedBy && (
                        <span>Shared by {shared.sharedBy.name}</span>
                      )}
                      <span>Last viewed {formatDate(shared.lastAccessedAt)}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {shared.shareUrl ? (
                      <Link to={shared.shareUrl}>
                        <Button variant="outline" size="sm">
                          <ExternalLink className="h-4 w-4 mr-1" />
                          View
                        </Button>
                      </Link>
                    ) : (
                      <Badge variant="outline" className="text-muted-foreground">
                        Link expired
                      </Badge>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-muted-foreground hover:text-destructive"
                      onClick={() => removeSharedMutation.mutate(shared.id)}
                      disabled={removeSharedMutation.isPending}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
