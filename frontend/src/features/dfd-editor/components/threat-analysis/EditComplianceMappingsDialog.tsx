import { useState, useMemo } from 'react'
import { Plus, Trash2, Shield, Check } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import {
  useFrameworks,
  useFrameworkRequirements,
  useInstanceMappings,
  useCreateInstanceMapping,
  useUpdateInstanceMapping,
  useDeleteInstanceMapping,
} from '@/features/compliance/api/compliance'
import type { ComplianceStandardMapping } from '../../types/threat-analysis'
import { mergeComplianceMappings } from './compliance-mapping-utils'

interface EditComplianceMappingsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  countermeasureId: number
  countermeasureName: string
  /**
   * The countermeasure's mappings as the threat analysis payload knows them:
   * library and instance merged, instance winning per requirement. A snapshot
   * taken when the dialog opens; the live instance list is fetched here.
   */
  knownMappings: ComplianceStandardMapping[]
  onSuccess?: () => void
}

export function EditComplianceMappingsDialog({
  open,
  onOpenChange,
  countermeasureId,
  countermeasureName,
  knownMappings,
  onSuccess,
}: EditComplianceMappingsDialogProps) {
  const [selectedFrameworkId, setSelectedFrameworkId] = useState<number | null>(null)
  const [selectedRequirementId, setSelectedRequirementId] = useState<number | null>(null)
  const [selectedSufficiency, setSelectedSufficiency] = useState<'full' | 'partial'>('partial')

  // Fetch frameworks
  const { data: frameworks, isLoading: frameworksLoading } = useFrameworks()

  // Fetch requirements for selected framework
  const { data: requirements, isLoading: requirementsLoading } = useFrameworkRequirements(
    selectedFrameworkId
  )

  // Fetch instance-level mappings
  const { data: instanceMappings, isLoading: instanceMappingsLoading } =
    useInstanceMappings(countermeasureId)

  // Mutations
  const createMapping = useCreateInstanceMapping()
  const updateMapping = useUpdateInstanceMapping()
  const deleteMapping = useDeleteInstanceMapping()

  // Known (payload) and live instance mappings, keyed by requirement so a
  // mapping present in both lists shows once as the editable instance row.
  const mergedMappings = useMemo(
    () => mergeComplianceMappings(knownMappings, instanceMappings),
    [knownMappings, instanceMappings]
  )

  // Filter requirements to exclude already mapped ones
  const availableRequirements = useMemo(() => {
    if (!requirements) return []
    const mappedIds = new Set(
      mergedMappings
        .filter((m) => m.requirementId != null)
        .map((m) => m.requirementId as number)
    )
    return requirements.filter((r) => !mappedIds.has(r.id))
  }, [requirements, mergedMappings])

  const handleAddMapping = () => {
    if (!selectedRequirementId) return

    const onMutationSuccess = () => {
      setSelectedRequirementId(null)
      setSelectedSufficiency('partial')
      onSuccess?.()
    }

    createMapping.mutate(
      { countermeasure: countermeasureId, requirement: selectedRequirementId, sufficiency: selectedSufficiency },
      { onSuccess: onMutationSuccess }
    )
  }

  const handleUpdateSufficiency = (mappingId: number, newSufficiency: 'full' | 'partial') => {
    updateMapping.mutate(
      { id: mappingId, sufficiency: newSufficiency },
      { onSuccess }
    )
  }

  const handleDeleteMapping = (mappingId: number) => {
    deleteMapping.mutate(mappingId, { onSuccess })
  }

  const isLoading = frameworksLoading || instanceMappingsLoading

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Edit Compliance Mappings
          </DialogTitle>
          <DialogDescription>
            Manage compliance requirement mappings for:{' '}
            <span className="font-medium">{countermeasureName}</span>
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="py-8 text-center text-muted-foreground">Loading...</div>
        ) : (
          <div className="space-y-4">
            {/* Current mappings */}
            <div className="space-y-2">
              <Label>Current Mappings</Label>
              <ScrollArea className="h-[200px] border rounded-md">
                {mergedMappings.length === 0 ? (
                  <div className="p-4 text-center text-muted-foreground">
                    No compliance mappings configured
                  </div>
                ) : (
                  <div className="p-2 space-y-2">
                    {mergedMappings.map((mapping) => (
                      <div
                        key={mapping.requirementId ?? `snapshot-${mapping.id}`}
                        className="flex items-start justify-between gap-2 p-2 rounded border bg-muted/30"
                      >
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="shrink-0">
                              {mapping.frameworkName}
                            </Badge>
                            <span className="font-medium text-sm">
                              {mapping.sectionCode}
                            </span>
                            {mapping.source === 'library' && (
                              <Badge
                                variant="secondary"
                                className="text-xs"
                                title="In the library pack but not on this countermeasure. Refresh compliance on the Compliance report to add it."
                              >
                                Library
                              </Badge>
                            )}
                            {mapping.source === 'snapshot' && (
                              <Badge variant="secondary" className="text-xs">
                                Historical
                              </Badge>
                            )}
                          </div>
                          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                            {mapping.requirementDescription}
                          </p>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {mapping.source === 'instance' ? (
                            <>
                              <Select
                                value={mapping.sufficiency}
                                onValueChange={(v) =>
                                  handleUpdateSufficiency(mapping.id!, v as 'full' | 'partial')
                                }
                              >
                                <SelectTrigger className="w-24 h-8 text-xs">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="full">Full</SelectItem>
                                  <SelectItem value="partial">Partial</SelectItem>
                                </SelectContent>
                              </Select>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-8 w-8 text-destructive hover:text-destructive"
                                onClick={() => handleDeleteMapping(mapping.id!)}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </>
                          ) : (
                            <Badge
                              variant="outline"
                              className={cn(
                                'text-xs',
                                mapping.sufficiency === 'full'
                                  ? 'bg-green-50 text-green-700 border-green-200'
                                  : 'bg-amber-50 text-amber-700 border-amber-200'
                              )}
                            >
                              {mapping.sufficiency}
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </ScrollArea>
            </div>

            {/* Add new mapping */}
            <div className="space-y-3 pt-3 border-t">
              <Label>Add New Mapping</Label>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Framework</Label>
                  <Select
                    value={selectedFrameworkId?.toString() ?? ''}
                    onValueChange={(v) => {
                      setSelectedFrameworkId(v ? parseInt(v, 10) : null)
                      setSelectedRequirementId(null)
                    }}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select framework..." />
                    </SelectTrigger>
                    <SelectContent>
                      {frameworks?.map((f) => (
                        <SelectItem key={f.id} value={f.id.toString()}>
                          {f.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Sufficiency</Label>
                  <Select
                    value={selectedSufficiency}
                    onValueChange={(v) => setSelectedSufficiency(v as 'full' | 'partial')}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="full">Full</SelectItem>
                      <SelectItem value="partial">Partial</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {selectedFrameworkId && (
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Requirement</Label>
                  {requirementsLoading ? (
                    <div className="text-sm text-muted-foreground py-2">Loading requirements...</div>
                  ) : availableRequirements.length === 0 ? (
                    <div className="text-sm text-muted-foreground py-2">
                      All requirements from this framework are already mapped
                    </div>
                  ) : (
                    <ScrollArea className="h-[150px] border rounded-md">
                      <div className="p-2 space-y-1">
                        {availableRequirements.map((r) => (
                          <button
                            key={r.id}
                            onClick={() => setSelectedRequirementId(r.id)}
                            className={cn(
                              'w-full text-left p-2 rounded-md transition-colors text-sm',
                              selectedRequirementId === r.id
                                ? 'bg-primary/10 border border-primary'
                                : 'hover:bg-muted'
                            )}
                          >
                            <div className="flex items-center gap-2">
                              {selectedRequirementId === r.id && (
                                <Check className="h-4 w-4 text-primary shrink-0" />
                              )}
                              <span className="font-medium">{r.sectionCode}</span>
                            </div>
                            <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                              {r.description}
                            </p>
                          </button>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </div>
              )}

              <Button
                onClick={handleAddMapping}
                disabled={!selectedRequirementId || createMapping.isPending}
                className="w-full"
              >
                <Plus className="h-4 w-4 mr-2" />
                Add Mapping
              </Button>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
