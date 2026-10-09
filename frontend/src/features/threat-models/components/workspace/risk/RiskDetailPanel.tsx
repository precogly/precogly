/**
 * The risk detail panel (plan 11.4, 11.11 Risk row): status beside the
 * read-only exposure, the one-sentence statement, domains, business
 * objectives (once the model has one), the linked threats with the picker,
 * the three ratings and the responses table.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { MultiSelectCombobox, type ComboboxOption } from '@/components/ui/multi-select-combobox'
import {
  useAddRiskThreats,
  useRemoveRiskThreats,
  useRisk,
  useUpdateRisk,
} from '@/features/threat-models/api/risks'
import { useBusinessObjectives } from '@/features/threat-models/api/threat-models'
import type { ComponentThreat } from '@/features/dfd-editor/types/threat-analysis'
import { RISK_DOMAINS, type RiskDomain } from '@/types/domain'
import { RISK_STATUSES, type Risk, type RiskStatus, type ScoringMethod, type UpdateRiskInput } from '@/types/risk'
import { RiskRatingSection } from './RiskRatingSection'
import { RiskResponsesTable, type OwnerOption } from './RiskResponsesTable'
import { ThreatPicker } from './ThreatPicker'
import {
  RISK_EXPOSURE_CLASSES,
  RISK_EXPOSURE_LABELS,
  RISK_STATUS_CLASSES,
  RISK_STATUS_LABELS,
  apiErrorMessage,
  threatPickerEntries,
  threatPickerLabel,
} from './risk-utils'

const NO_OWNER = '_none'

const DOMAIN_OPTIONS: ComboboxOption[] = RISK_DOMAINS.map((entry) => ({ value: entry.value, label: entry.label }))

export function RiskStatusBadge({ status }: { status: RiskStatus }) {
  return (
    <Badge variant="outline" className={RISK_STATUS_CLASSES[status]}>
      {RISK_STATUS_LABELS[status] ?? status}
    </Badge>
  )
}

export function RiskExposureBadge({ exposure }: { exposure: Risk['exposure'] }) {
  return (
    <Badge variant="outline" className={RISK_EXPOSURE_CLASSES[exposure] ?? ''} title="Derived from the linked threats">
      {RISK_EXPOSURE_LABELS[exposure] ?? exposure}
    </Badge>
  )
}

/**
 * A text field that writes on blur when its value changed. A new server
 * value (another write came back, or another risk was selected) resets the
 * draft during render, the pattern React recommends over an effect.
 */
function useBlurSave(serverValue: string, save: (next: string) => void) {
  const [draft, setDraft] = useState(serverValue)
  const [lastServerValue, setLastServerValue] = useState(serverValue)
  if (serverValue !== lastServerValue) {
    setLastServerValue(serverValue)
    setDraft(serverValue)
  }
  const commit = () => {
    if (draft !== serverValue) save(draft)
  }
  return { draft, setDraft, commit }
}

export interface RiskDetailPanelProps {
  threatModelId: string
  risk: Risk
  componentThreats: ComponentThreat[]
  owners: OwnerOption[]
  scoringMethod: ScoringMethod | undefined
  scoringMethods: ScoringMethod[] | undefined
  onClose: () => void
}

export function RiskDetailPanel({
  threatModelId,
  risk,
  componentThreats,
  owners,
  scoringMethod,
  scoringMethods,
  onClose,
}: RiskDetailPanelProps) {
  const { data: riskDetail } = useRisk(threatModelId, risk.id)
  const displayRisk = riskDetail ?? risk
  const updateRisk = useUpdateRisk(threatModelId)
  const addThreats = useAddRiskThreats(threatModelId)
  const removeThreats = useRemoveRiskThreats(threatModelId)
  const { data: businessObjectives = [] } = useBusinessObjectives(threatModelId)

  const patchRisk = (data: UpdateRiskInput, failure: string) => {
    updateRisk.mutate(
      { riskId: risk.id, data },
      { onError: (error) => toast.error(apiErrorMessage(error, failure)) }
    )
  }

  const nameField = useBlurSave(displayRisk.name, (name) => {
    if (name.trim()) patchRisk({ name: name.trim() }, 'Failed to rename the risk.')
  })
  const descriptionField = useBlurSave(displayRisk.description ?? '', (description) =>
    patchRisk({ description }, 'Failed to save the description.')
  )
  const statementField = useBlurSave(displayRisk.statement ?? '', (statement) =>
    patchRisk({ statement }, 'Failed to save the statement.')
  )

  const pickerEntries = useMemo(() => threatPickerEntries(componentThreats), [componentThreats])
  const linkedThreats = displayRisk.threats ?? []
  const linkedThreatIds = linkedThreats.map((entry) => entry.threatId)

  const handleToggleThreat = (threatId: number, nextSelected: boolean) => {
    const mutation = nextSelected ? addThreats : removeThreats
    mutation.mutate(
      { riskId: risk.id, data: { threatIds: [threatId] } },
      {
        onError: (error) =>
          toast.error(apiErrorMessage(error, nextSelected ? 'Failed to link the threat.' : 'Failed to unlink the threat.')),
      }
    )
  }

  const objectiveOptions: ComboboxOption[] = businessObjectives.map((objective) => ({
    value: String(objective.id),
    label: objective.name,
  }))
  const selectedObjectiveIds =
    displayRisk.businessObjectiveIds ?? displayRisk.businessObjectives?.map((objective) => objective.id) ?? []

  return (
    <Card className="border-l-2 border-l-primary" data-testid="risk-detail">
      <CardHeader className="pb-3 space-y-2">
        <div className="flex items-start justify-between gap-2">
          <Input
            value={nameField.draft}
            onChange={(event) => nameField.setDraft(event.target.value)}
            onBlur={nameField.commit}
            className="text-lg font-semibold h-9"
            aria-label="Risk name"
          />
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close risk">
            <X className="h-4 w-4" />
          </Button>
        </div>
        <Textarea
          value={descriptionField.draft}
          onChange={(event) => descriptionField.setDraft(event.target.value)}
          onBlur={descriptionField.commit}
          rows={2}
          placeholder="Description"
          className="text-sm"
          aria-label="Risk description"
        />
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">Status</Label>
            <Select
              value={displayRisk.status}
              onValueChange={(value) => patchRisk({ status: value as RiskStatus }, 'Failed to change the status.')}
            >
              <SelectTrigger className="h-8" aria-label="Risk status">
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
            <Label className="text-xs text-muted-foreground">Exposure (from linked threats)</Label>
            <div className="h-8 flex items-center">
              <RiskExposureBadge exposure={displayRisk.exposure} />
            </div>
          </div>
        </div>

        <div className="space-y-1">
          <Label htmlFor={`risk-statement-${risk.id}`} className="text-xs text-muted-foreground">
            Statement
          </Label>
          <Textarea
            id={`risk-statement-${risk.id}`}
            value={statementField.draft}
            onChange={(event) => statementField.setDraft(event.target.value)}
            onBlur={statementField.commit}
            rows={2}
            placeholder="A ransomware crew encrypts the control network, stopping line 3 for days."
          />
          <p className="text-xs text-muted-foreground">Source, event and impact in one sentence.</p>
        </div>

        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground">Domains</Label>
          <MultiSelectCombobox
            options={DOMAIN_OPTIONS}
            selected={displayRisk.domains ?? []}
            onChange={(selected) => patchRisk({ domains: selected as RiskDomain[] }, 'Failed to save the domains.')}
            placeholder="Add a domain"
            searchPlaceholder="Search domains"
            emptyMessage="No such domain."
          />
        </div>

        {businessObjectives.length > 0 && (
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">Business objectives</Label>
            <MultiSelectCombobox
              options={objectiveOptions}
              selected={selectedObjectiveIds.map(String)}
              onChange={(selected) =>
                patchRisk({ businessObjectiveIds: selected.map(Number) }, 'Failed to save the business objectives.')
              }
              placeholder="Objectives this risk threatens"
              searchPlaceholder="Search objectives"
              emptyMessage="No such objective."
            />
          </div>
        )}

        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground">Owner</Label>
          <Select
            value={displayRisk.owner === null ? NO_OWNER : String(displayRisk.owner)}
            onValueChange={(value) =>
              patchRisk({ owner: value === NO_OWNER ? null : Number(value) }, 'Failed to change the owner.')
            }
          >
            <SelectTrigger className="h-8" aria-label="Risk owner">
              <SelectValue placeholder="No owner" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={NO_OWNER}>No owner</SelectItem>
              {owners.map((owner) => (
                <SelectItem key={owner.userId} value={String(owner.userId)}>
                  {owner.email}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">Linked threats ({linkedThreats.length})</p>
          {linkedThreats.length > 0 && (
            <div className="space-y-1">
              {linkedThreats.map((threat) => (
                <div
                  key={threat.riskThreatId}
                  className="flex items-center justify-between gap-2 text-sm border rounded px-2 py-1"
                >
                  <span className="truncate flex-1 min-w-0" title={threatPickerLabel(threat)}>
                    <span className="font-mono text-xs text-muted-foreground mr-1">{threat.displayNumber}</span>
                    {threatPickerLabel(threat).slice(threat.displayNumber.length + 1)}
                  </span>
                  <Badge
                    variant="outline"
                    className={
                      threat.status === 'mitigated'
                        ? 'bg-green-50 text-green-700'
                        : threat.status === 'addressable'
                          ? 'bg-amber-50 text-amber-700'
                          : 'bg-red-50 text-red-700'
                    }
                  >
                    {threat.status}
                  </Badge>
                </div>
              ))}
            </div>
          )}
          <ThreatPicker
            entries={pickerEntries}
            selectedThreatIds={linkedThreatIds}
            onToggle={handleToggleThreat}
            triggerLabel="Link threats"
            busy={addThreats.isPending || removeThreats.isPending}
          />
        </div>

        <RiskRatingSection
          threatModelId={threatModelId}
          risk={displayRisk}
          scoringMethod={scoringMethod}
          scoringMethods={scoringMethods}
        />

        <RiskResponsesTable
          threatModelId={threatModelId}
          riskId={risk.id}
          initialResponses={displayRisk.responses}
          owners={owners}
          componentThreats={componentThreats}
        />

        <div className="text-xs text-muted-foreground pt-2 border-t">
          <p>Method: {scoringMethod?.label ?? displayRisk.scoringMethod}</p>
          <p>Created: {new Date(displayRisk.createdAt).toLocaleDateString()}</p>
        </div>
      </CardContent>
    </Card>
  )
}
