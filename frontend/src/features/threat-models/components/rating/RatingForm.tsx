/**
 * A controlled form producing the backend's `rating_inputs` (#31 comment,
 * section 2.8; plan 11.11 "Rating form" row).
 *
 * Three modes, picked by `method`:
 *  - `qualitative-matrix`: likelihood x impact selects (the 5x5 matrix).
 *  - `owasp-risk-rating`: the sixteen OWASP factors in four groups.
 *  - `manual`: a level with a rationale (what a threat gets when the model's
 *    method has no engine, and what `fair` and `mozilla-rra` fall back to).
 *
 * The "Advanced" section holds the impact categories and the amount,
 * currency and range (`impactCategories`, `impactQuantification`), which no
 * engine fills in. The output is the camelCase form of `rating_inputs`; the
 * API layer writes it as snake_case, nested keys included.
 */

import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { MultiSelectCombobox } from '@/components/ui/multi-select-combobox'
import { cn } from '@/lib/utils'
import { IMPACT_CATEGORIES, type ImpactCategory } from '@/types/domain'
import {
  MATRIX_IMPACTS,
  MATRIX_LIKELIHOODS,
  OWASP_GROUPS,
  RATING_LEVELS,
  isLevelOnlyInputs,
  isMatrixInputs,
  isOwaspInputs,
  type ImpactExtraInputs,
  type ImpactQuantification,
  type LevelOnlyRatingInputs,
  type MatrixImpact,
  type MatrixLikelihood,
  type OwaspGroupKey,
  type OwaspRiskRatingInputs,
  type QualitativeMatrixRatingInputs,
  type RatingInputs,
  type RatingLevel,
  type ScoringFieldSchema,
  type ScoringMethod,
} from '@/types/risk'
import { emptyRatingInputs, ratingFormMode, type RatingFormMethod } from './rating-form-utils'

const OWASP_FACTOR_LABELS: Record<string, string> = {
  skillLevel: 'Skill level',
  motive: 'Motive',
  opportunity: 'Opportunity',
  size: 'Size',
  easeOfDiscovery: 'Ease of discovery',
  easeOfExploit: 'Ease of exploit',
  awareness: 'Awareness',
  intrusionDetection: 'Intrusion detection',
  lossOfConfidentiality: 'Loss of confidentiality',
  lossOfIntegrity: 'Loss of integrity',
  lossOfAvailability: 'Loss of availability',
  lossOfAccountability: 'Loss of accountability',
  financialDamage: 'Financial damage',
  reputationDamage: 'Reputation damage',
  nonCompliance: 'Non-compliance',
  privacyViolation: 'Privacy violation',
}

export interface RatingFormProps {
  /** The model's `riskScoringMethod`, or `manual` for a level-only rating. */
  method: RatingFormMethod | string
  /** The method's schema from `/scoring-methods/`, for the OWASP option labels. Optional. */
  scoringMethod?: ScoringMethod
  value: RatingInputs
  onChange: (value: RatingInputs) => void
  disabled?: boolean
  /** Hide the rationale textarea (for compact dialogs). */
  hideRationale?: boolean
  /** Start with the Advanced section open. */
  advancedOpen?: boolean
  className?: string
}

export function RatingForm({
  method,
  scoringMethod,
  value,
  onChange,
  disabled = false,
  hideRationale = false,
  advancedOpen = false,
  className,
}: RatingFormProps) {
  const mode = ratingFormMode(method)
  const [showAdvanced, setShowAdvanced] = useState(advancedOpen)

  // The value may still carry another mode's keys when the method changes;
  // the mode-specific editors below read what they need and write a fresh
  // object of their own shape, keeping the impact section.
  const impactExtra: ImpactExtraInputs = useMemo(
    () => ({
      ...(value.impactCategories && { impactCategories: value.impactCategories }),
      ...(value.impactQuantification && { impactQuantification: value.impactQuantification }),
    }),
    [value.impactCategories, value.impactQuantification]
  )

  const rationale = value.rationale ?? ''

  const updateImpactExtra = (patch: ImpactExtraInputs) => {
    onChange({ ...value, ...patch })
  }

  const updateRationale = (nextRationale: string) => {
    onChange({ ...value, rationale: nextRationale })
  }

  return (
    <div className={cn('space-y-4', className)}>
      {mode === 'qualitative-matrix' && (
        <MatrixEditor
          value={value}
          impactExtra={impactExtra}
          rationale={rationale}
          disabled={disabled}
          onChange={onChange}
        />
      )}
      {mode === 'owasp-risk-rating' && (
        <OwaspEditor
          value={value}
          impactExtra={impactExtra}
          rationale={rationale}
          scoringMethod={scoringMethod}
          disabled={disabled}
          onChange={onChange}
        />
      )}
      {mode === 'manual' && (
        <LevelEditor
          value={value}
          impactExtra={impactExtra}
          rationale={rationale}
          disabled={disabled}
          onChange={onChange}
        />
      )}

      {!hideRationale && (
        <div className="space-y-1">
          <Label htmlFor="rating-rationale" className="text-xs">
            Rationale
          </Label>
          <Textarea
            id="rating-rationale"
            value={rationale}
            disabled={disabled}
            rows={2}
            placeholder="Why this rating"
            onChange={(event) => updateRationale(event.target.value)}
          />
        </div>
      )}

      <div className="border-t pt-2">
        <button
          type="button"
          className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground"
          onClick={() => setShowAdvanced((open) => !open)}
          aria-expanded={showAdvanced}
        >
          {showAdvanced ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          Advanced
        </button>
        {showAdvanced && (
          <ImpactAdvancedEditor
            categories={value.impactCategories ?? []}
            quantification={value.impactQuantification ?? {}}
            disabled={disabled}
            onChange={updateImpactExtra}
          />
        )}
      </div>
    </div>
  )
}

interface ModeEditorProps {
  value: RatingInputs
  impactExtra: ImpactExtraInputs
  rationale: string
  disabled: boolean
  onChange: (value: RatingInputs) => void
}

function LevelEditor({ value, impactExtra, rationale, disabled, onChange }: ModeEditorProps) {
  const level: RatingLevel = isLevelOnlyInputs(value) ? value.level : 'medium'
  return (
    <div className="space-y-1">
      <Label className="text-xs">Level</Label>
      <Select
        value={level}
        disabled={disabled}
        onValueChange={(next) => {
          const nextInputs: LevelOnlyRatingInputs = { level: next as RatingLevel, rationale, ...impactExtra }
          onChange(nextInputs)
        }}
      >
        <SelectTrigger className="h-8 text-xs" aria-label="Level">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {RATING_LEVELS.map((entry) => (
            <SelectItem key={entry.value} value={entry.value}>
              {entry.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}

function MatrixEditor({ value, impactExtra, rationale, disabled, onChange }: ModeEditorProps) {
  const likelihood: MatrixLikelihood = isMatrixInputs(value) ? value.likelihood : 'possible'
  const impact: MatrixImpact = isMatrixInputs(value) ? value.impact : 'moderate'
  const emit = (nextLikelihood: MatrixLikelihood, nextImpact: MatrixImpact) => {
    const nextInputs: QualitativeMatrixRatingInputs = {
      likelihood: nextLikelihood,
      impact: nextImpact,
      rationale,
      ...impactExtra,
    }
    onChange(nextInputs)
  }
  return (
    <div className="grid grid-cols-2 gap-3">
      <div className="space-y-1">
        <Label className="text-xs">Likelihood</Label>
        <Select value={likelihood} disabled={disabled} onValueChange={(next) => emit(next as MatrixLikelihood, impact)}>
          <SelectTrigger className="h-8 text-xs" aria-label="Likelihood">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {MATRIX_LIKELIHOODS.map((entry) => (
              <SelectItem key={entry.value} value={entry.value}>
                {entry.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Impact</Label>
        <Select value={impact} disabled={disabled} onValueChange={(next) => emit(likelihood, next as MatrixImpact)}>
          <SelectTrigger className="h-8 text-xs" aria-label="Impact">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {MATRIX_IMPACTS.map((entry) => (
              <SelectItem key={entry.value} value={entry.value}>
                {entry.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </div>
  )
}

function OwaspEditor({
  value,
  impactExtra,
  rationale,
  scoringMethod,
  disabled,
  onChange,
}: ModeEditorProps & { scoringMethod?: ScoringMethod }) {
  const current: OwaspRiskRatingInputs = isOwaspInputs(value)
    ? value
    : (emptyRatingInputs('owasp-risk-rating') as OwaspRiskRatingInputs)

  const setFactor = (groupKey: OwaspGroupKey, field: string, score: number) => {
    const group = { ...(current[groupKey] as Record<string, number>), [field]: score }
    const nextInputs: OwaspRiskRatingInputs = {
      ...current,
      [groupKey]: group,
      rationale,
      ...impactExtra,
    }
    onChange(nextInputs)
  }

  return (
    <div className="space-y-3">
      {OWASP_GROUPS.map((group) => {
        const groupSchema = scoringMethod?.inputSchema?.[group.key]
        const values = current[group.key] as Record<string, number>
        return (
          <fieldset key={group.key} className="space-y-2 rounded-md border p-2">
            <legend className="px-1 text-xs font-medium">{groupSchema?.label ?? group.label}</legend>
            <div className="grid grid-cols-2 gap-2">
              {group.fields.map((field) => {
                const fieldSchema = groupSchema?.fields?.[field]
                return (
                  <OwaspFactorSelect
                    key={field}
                    field={field}
                    schema={fieldSchema}
                    value={values?.[field] ?? 0}
                    disabled={disabled}
                    onChange={(score) => setFactor(group.key, field, score)}
                  />
                )
              })}
            </div>
          </fieldset>
        )
      })}
    </div>
  )
}

function OwaspFactorSelect({
  field,
  schema,
  value,
  disabled,
  onChange,
}: {
  field: string
  schema?: ScoringFieldSchema
  value: number
  disabled: boolean
  onChange: (score: number) => void
}) {
  const min = schema?.min ?? 0
  const max = schema?.max ?? 9
  const labels = schema?.labels ?? []
  const options = Array.from({ length: max - min + 1 }, (_, index) => min + index)
  return (
    <div className="space-y-1">
      <Label className="text-[11px]">{OWASP_FACTOR_LABELS[field] ?? field}</Label>
      <Select value={String(value)} disabled={disabled} onValueChange={(next) => onChange(Number(next))}>
        <SelectTrigger className="h-8 text-xs" aria-label={OWASP_FACTOR_LABELS[field] ?? field}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map((score) => {
            const label = labels[score - min]
            return (
              <SelectItem key={score} value={String(score)}>
                {score}
                {label ? ` - ${label}` : ''}
              </SelectItem>
            )
          })}
        </SelectContent>
      </Select>
    </div>
  )
}

function ImpactAdvancedEditor({
  categories,
  quantification,
  disabled,
  onChange,
}: {
  categories: ImpactCategory[]
  quantification: ImpactQuantification
  disabled: boolean
  onChange: (patch: ImpactExtraInputs) => void
}) {
  const range = quantification.financialLossRange ?? {}

  const setQuantification = (patch: Partial<ImpactQuantification>) => {
    const next: ImpactQuantification = { ...quantification, ...patch }
    onChange({ impactCategories: categories, impactQuantification: next })
  }

  const setRange = (key: 'minimum' | 'mostLikely' | 'maximum', raw: string) => {
    const nextRange = { ...range }
    if (raw === '') delete nextRange[key]
    else nextRange[key] = Number(raw)
    setQuantification({ financialLossRange: nextRange })
  }

  const numberOrEmpty = (amount: number | undefined) => (amount === undefined ? '' : String(amount))

  return (
    <div className="mt-2 space-y-3">
      <div className="space-y-1">
        <Label className="text-xs">Impact categories</Label>
        <MultiSelectCombobox
          options={IMPACT_CATEGORIES.map((entry) => ({ value: entry.value, label: entry.label }))}
          selected={categories}
          onChange={(selected) =>
            onChange({ impactCategories: selected as ImpactCategory[], impactQuantification: quantification })
          }
          placeholder="Select categories"
          className={cn(disabled && 'pointer-events-none opacity-60')}
        />
      </div>
      <div className="grid grid-cols-3 gap-2">
        <div className="space-y-1">
          <Label htmlFor="rating-financial-loss" className="text-xs">
            Amount
          </Label>
          <Input
            id="rating-financial-loss"
            type="number"
            min={0}
            className="h-8 text-xs"
            value={numberOrEmpty(quantification.financialLoss)}
            disabled={disabled}
            onChange={(event) =>
              setQuantification({
                financialLoss: event.target.value === '' ? undefined : Number(event.target.value),
              })
            }
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="rating-currency" className="text-xs">
            Currency
          </Label>
          <Input
            id="rating-currency"
            className="h-8 text-xs uppercase"
            maxLength={3}
            placeholder="USD"
            value={quantification.currency ?? ''}
            disabled={disabled}
            onChange={(event) =>
              setQuantification({ currency: event.target.value.toUpperCase() || undefined })
            }
          />
        </div>
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Range (minimum, most likely, maximum)</Label>
        <div className="grid grid-cols-3 gap-2">
          <Input
            type="number"
            min={0}
            className="h-8 text-xs"
            aria-label="Minimum"
            placeholder="Min"
            value={numberOrEmpty(range.minimum)}
            disabled={disabled}
            onChange={(event) => setRange('minimum', event.target.value)}
          />
          <Input
            type="number"
            min={0}
            className="h-8 text-xs"
            aria-label="Most likely"
            placeholder="Most likely"
            value={numberOrEmpty(range.mostLikely)}
            disabled={disabled}
            onChange={(event) => setRange('mostLikely', event.target.value)}
          />
          <Input
            type="number"
            min={0}
            className="h-8 text-xs"
            aria-label="Maximum"
            placeholder="Max"
            value={numberOrEmpty(range.maximum)}
            disabled={disabled}
            onChange={(event) => setRange('maximum', event.target.value)}
          />
        </div>
      </div>
    </div>
  )
}
