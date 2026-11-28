import { AlertTriangle, Loader2, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import type { ValidationResult } from '@/features/libraries/types/packs'
import { onlyWaitingForFrameworks } from './pack-list-helpers'

export interface FailedImportSummary {
  /** The dependency that failed, by name. */
  dependencyName: string
  /** "Imported: ...", "Failed: ...", "Not imported: ...", each only when it has packs. */
  lines: string[]
}

export function ValidationWarningsDialog({
  validationResult,
  open,
  onOpenChange,
  onImportAnyway,
  isImporting = false,
  failedImport = null,
  progressLine = null,
}: {
  validationResult: ValidationResult | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onImportAnyway?: () => void
  isImporting?: boolean
  /** Set when a dependency failed while importing another pack. */
  failedImport?: FailedImportSummary | null
  /** For the requested pack's own warnings: the dependencies imported before it. */
  progressLine?: string | null
}) {
  if (!validationResult) return null

  const hasErrors = validationResult.errorCount > 0
  const hasWarnings = validationResult.warningCount > 0
  // "Import anyway" never applies to a dependency.
  const canImportAnyway = hasWarnings && !hasErrors && onImportAnyway && !failedImport
  const pendingDependencyCount = validationResult.pendingDependencies?.length ?? 0
  // Only frameworks not imported yet: nothing is wrong, the mappings wait for them.
  const onlyWaiting = !failedImport && onlyWaitingForFrameworks(validationResult)

  return (
    <Dialog open={open} onOpenChange={isImporting ? undefined : onOpenChange}>
      <DialogContent className="max-w-lg max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>
            {failedImport
              ? `${failedImport.dependencyName} could not be imported`
              : onlyWaiting
                ? 'Some mappings are waiting for a framework'
                : 'Validation Issues Found'}
          </DialogTitle>
          <DialogDescription>
            {validationResult.packName}
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-3 py-4">
          {failedImport && (
            <div className="space-y-1 text-sm" data-testid="failed-import-summary">
              {failedImport.lines.map((line) => (
                <p key={line}>{line}</p>
              ))}
            </div>
          )}

          {progressLine && !failedImport && (
            <p className="text-sm text-muted-foreground" data-testid="dependencies-imported-line">
              {progressLine}
            </p>
          )}

          {pendingDependencyCount > 0 && (
            <p className="text-sm text-muted-foreground" data-testid="pending-dependencies">
              {pendingDependencyCount} {pendingDependencyCount === 1 ? 'dependency is' : 'dependencies are'} not
              imported yet. Import brings them in first, and warnings about them go away then.
            </p>
          )}

          {/* Errors */}
          {hasErrors && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium text-red-800">
                Errors ({validationResult.errorCount})
              </h4>
              {validationResult.errors.map((error, index) => (
                <div
                  key={index}
                  className="p-3 bg-red-50 border border-red-200 rounded-md"
                >
                  <div className="flex items-start gap-2">
                    <XCircle className="h-4 w-4 text-red-600 mt-0.5 shrink-0" />
                    <div className="text-sm">
                      <p className="text-red-800 font-medium">{error.message}</p>
                      <p className="text-red-600 mt-1">
                        File: {error.file}
                        {error.reference && <> | Reference: {error.reference}</>}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {onlyWaiting && (
            <div className="space-y-2 text-sm" data-testid="waiting-frameworks">
              <p>
                These frameworks aren&apos;t imported yet. {validationResult.packName}&apos;s mappings to them
                are kept and show up when you import them.
              </p>
              <ul className="list-disc pl-5 text-muted-foreground">
                {validationResult.warnings.map((warning) => (
                  <li key={warning.waitingForFramework}>{warning.waitingForFramework}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Warnings */}
          {hasWarnings && !onlyWaiting && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium text-amber-800">
                Warnings ({validationResult.warningCount})
              </h4>
              {validationResult.warnings.map((warning, index) => (
                <div
                  key={index}
                  className="p-3 bg-amber-50 border border-amber-200 rounded-md"
                >
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 shrink-0" />
                    <div className="text-sm">
                      <p className="text-amber-800">{warning.message}</p>
                      <p className="text-amber-600 mt-1">
                        File: {warning.file} | Field: {warning.field}
                      </p>
                      <p className="text-amber-700 mt-1 font-medium">
                        Fix: {warning.suggestion}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isImporting}>
            Close
          </Button>
          {canImportAnyway && (
            <Button onClick={onImportAnyway} disabled={isImporting}>
              {isImporting && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
              {onlyWaiting ? 'Import' : 'Import Anyway'}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
