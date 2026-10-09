/**
 * The "Add risk" dialog (plan 11.4): name, statement, description, status,
 * owner, domains, business objectives (once the model has one), the rating
 * with the model's method, and the threats to link.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { MultiSelectCombobox, type ComboboxOption } from '@/components/ui/multi-select-combobox'
import { useCreateRisk } from '@/features/threat-models/api/risks'
import { useBusinessObjectives } from '@/features/threat-models/api/threat-models'
import { RatingForm, emptyRatingInputs, ratingInputsComplete } from '@/features/threat-models/components/rating'
import type { ComponentThreat } from '@/features/dfd-editor/types/threat-analysis'
import { RISK_DOMAINS, type RiskDomain } from '@/types/domain'
import {
  RISK_STATUSES,
  type CreateRiskInput,
  type RatingInputs,
  type RiskStatus,
  type ScoringMethod,
  type ScoringMethodKey,
} from '@/types/risk'
import type { OwnerOption } from './RiskResponsesTable'
import { ThreatPicker } from './ThreatPicker'
import { apiErrorMessage, threatPickerEntries } from './risk-utils'

const NO_OWNER = '_none'

const DOMAIN_OPTIONS: ComboboxOption[] = RISK_DOMAINS.map((entry) => ({ value: entry.value, label: entry.label }))

export interface AddRiskDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
  componentThreats: ComponentThreat[]
  owners: OwnerOption[]
  scoringMethodKey: ScoringMethodKey
  scoringMethod: ScoringMethod | undefined
}

export function AddRiskDialog({
  open,
  onOpenChange,
  threatModelId,
  componentThreats,
  owners,
  scoringMethodKey,
  scoringMethod,
}: AddRiskDialogProps) {
  // A method without an engine (fair, mozilla-rra) rates by level (manual).
  const ratingMethod = scoringMethod?.available ? scoringMethodKey : 'manual'
  const [name, setName] = useState('')
  const [statement, setStatement] = useState('')
  const [description, setDescription] = useState('')
  const [riskStatus, setRiskStatus] = useState<RiskStatus>('identified')
  const [owner, setOwner] = useState<number | null>(null)
  const [domains, setDomains] = useState<RiskDomain[]>([])
  const [businessObjectiveIds, setBusinessObjectiveIds] = useState<number[]>([])
  const [ratingInputs, setRatingInputs] = useState<RatingInputs>(() => emptyRatingInputs(ratingMethod))
  const [selectedThreatIds, setSelectedThreatIds] = useState<number[]>([])

  const createRisk = useCreateRisk(threatModelId)
  const { data: businessObjectives = [] } = useBusinessObjectives(threatModelId)
  const pickerEntries = useMemo(() => threatPickerEntries(componentThreats), [componentThreats])

  const objectiveOptions: ComboboxOption[] = businessObjectives.map((objective) => ({
    value: String(objective.id),
    label: objective.name,
  }))

  const handleToggleThreat = (threatId: number, nextSelected: boolean) => {
    setSelectedThreatIds((previous) =>
      nextSelected ? [...previous.filter((id) => id !== threatId), threatId] : previous.filter((id) => id !== threatId)
    )
  }

  const resetForm = () => {
    setName('')
    setStatement('')
    setDescription('')
    setRiskStatus('identified')
    setOwner(null)
    setDomains([])
    setBusinessObjectiveIds([])
    setRatingInputs(emptyRatingInputs(ratingMethod))
    setSelectedThreatIds([])
  }

  const handleSubmit = () => {
    const input: CreateRiskInput = {
      name: name.trim(),
      statement,
      description,
      ratingInputs,
      status: riskStatus,
      owner,
      domains,
      businessObjectiveIds,
      threatIds: selectedThreatIds,
    }
    createRisk.mutate(input, {
      onSuccess: () => {
        onOpenChange(false)
        resetForm()
      },
      onError: (error) => toast.error(apiErrorMessage(error, 'Failed to create the risk.')),
    })
  }

  const canSubmit = Boolean(name.trim()) && ratingInputsComplete(ratingInputs)

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next)
        if (!next) resetForm()
      }}
    >
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add risk</DialogTitle>
          <DialogDescription>Describe the risk and rate it with the model's method.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1">
            <Label htmlFor="new-risk-name">
              Name<span className="text-destructive ml-0.5">*</span>
            </Label>
            <Input
              id="new-risk-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Risk name"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="new-risk-statement">Statement</Label>
            <Textarea
              id="new-risk-statement"
              value={statement}
              onChange={(event) => setStatement(event.target.value)}
              rows={2}
            />
            <p className="text-xs text-muted-foreground">Source, event and impact in one sentence.</p>
          </div>
          <div className="space-y-1">
            <Label htmlFor="new-risk-description">Description</Label>
            <Textarea
              id="new-risk-description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              rows={2}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>Status</Label>
              <Select value={riskStatus} onValueChange={(value) => setRiskStatus(value as RiskStatus)}>
                <SelectTrigger aria-label="Status">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {RISK_STATUSES.map((entry) => (
                    <SelectItem key={entry.value} value={entry.value}>
                      {entry.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Owner</Label>
              <Select
                value={owner === null ? NO_OWNER : String(owner)}
                onValueChange={(value) => setOwner(value === NO_OWNER ? null : Number(value))}
              >
                <SelectTrigger aria-label="Owner">
                  <SelectValue placeholder="Select owner" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NO_OWNER}>No owner</SelectItem>
                  {owners.map((member) => (
                    <SelectItem key={member.userId} value={String(member.userId)}>
                      {member.email}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-1">
            <Label>Domains</Label>
            <MultiSelectCombobox
              options={DOMAIN_OPTIONS}
              selected={domains}
              onChange={(selected) => setDomains(selected as RiskDomain[])}
              placeholder="Add a domain"
              searchPlaceholder="Search domains"
              emptyMessage="No such domain."
            />
          </div>
          {businessObjectives.length > 0 && (
            <div className="space-y-1">
              <Label>Business objectives</Label>
              <MultiSelectCombobox
                options={objectiveOptions}
                selected={businessObjectiveIds.map(String)}
                onChange={(selected) => setBusinessObjectiveIds(selected.map(Number))}
                placeholder="Objectives this risk threatens"
                searchPlaceholder="Search objectives"
                emptyMessage="No such objective."
              />
            </div>
          )}
          <div className="space-y-1">
            <Label>
              Rating<span className="text-destructive ml-0.5">*</span>
            </Label>
            <RatingForm
              method={ratingMethod}
              scoringMethod={scoringMethod}
              value={ratingInputs}
              onChange={setRatingInputs}
            />
          </div>
          <div className="space-y-1">
            <Label>Link threats (optional)</Label>
            <ThreatPicker
              entries={pickerEntries}
              selectedThreatIds={selectedThreatIds}
              onToggle={handleToggleThreat}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit || createRisk.isPending}>
            {createRisk.isPending && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
            Create risk
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
