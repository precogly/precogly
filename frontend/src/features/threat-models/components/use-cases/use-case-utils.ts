/**
 * Pure logic for the use case and abuse case dialogs: payload building from
 * form state, gap badge rules, flow labels and backend error messages.
 */

import type {
  AbuseCase,
  AbuseCaseFlowData,
  AbuseCaseInput,
  AlternativeFlow,
  FlowStep,
  UseCase,
  UseCaseException,
  UseCaseFlowData,
  UseCaseInput,
} from '@/features/threat-models/types/core'

/** "Source to Destination (name)"; the parentheses are left out when the name is empty. */
export function formatFlowLabel(flow: { name: string; sourceName: string; destinationName: string }): string {
  const route = `${flow.sourceName} to ${flow.destinationName}`
  const name = flow.name.trim()
  return name ? `${route} (${name})` : route
}

/** Trim rows and drop the empty ones. */
export function cleanStringList(rows: string[]): string[] {
  return rows.map((row) => row.trim()).filter((row) => row.length > 0)
}

/** Trim descriptions, drop steps without one, and keep an imported `actor` as it was. */
export function cleanSteps(steps: FlowStep[]): FlowStep[] {
  return steps
    .map((step) => ({ ...step, description: step.description.trim() }))
    .filter((step) => step.description.length > 0)
}

function isBlank(...values: (string | undefined)[]): boolean {
  return values.every((value) => !value || value.trim().length === 0)
}

export function cleanAlternativeFlows(flows: AlternativeFlow[]): AlternativeFlow[] {
  return flows
    .filter((flow) => !(isBlank(flow.name, flow.condition, flow.description) && cleanSteps(flow.steps ?? []).length === 0))
    .map((flow) => {
      const cleaned: AlternativeFlow = { ...flow, name: flow.name.trim(), condition: flow.condition.trim() }
      const description = flow.description?.trim()
      if (description) cleaned.description = description
      else delete cleaned.description
      const steps = cleanSteps(flow.steps ?? [])
      if (steps.length > 0) cleaned.steps = steps
      else delete cleaned.steps
      return cleaned
    })
}

export function cleanExceptions(exceptions: UseCaseException[]): UseCaseException[] {
  return exceptions
    .filter((exception) => !isBlank(exception.name, exception.condition, exception.description, exception.handling))
    .map((exception) => {
      const cleaned: UseCaseException = { ...exception, name: exception.name.trim(), condition: exception.condition.trim() }
      const description = exception.description?.trim()
      if (description) cleaned.description = description
      else delete cleaned.description
      const handling = exception.handling?.trim()
      if (handling) cleaned.handling = handling
      else delete cleaned.handling
      return cleaned
    })
}

/**
 * Set a list key: sent when it has rows, or when the saved data had the key
 * (so clearing the last row clears it on the server).
 */
function assignList<T>(target: Record<string, unknown>, key: string, rows: T[]) {
  if (rows.length > 0 || key in target) target[key] = rows
}

// ---- Use case ----

export interface UseCaseFormState {
  name: string
  description: string
  componentIds: number[]
  flowIds: number[]
  businessObjectiveIds: number[]
  preconditions: string[]
  postconditions: string[]
  successCriteria: string[]
  mainFlow: FlowStep[]
  alternativeFlows: AlternativeFlow[]
  exceptions: UseCaseException[]
  /** The saved flowData; keys the form does not edit (notes, unknown keys) are kept. */
  baseFlowData: UseCaseFlowData
}

export function initialUseCaseForm(useCase?: UseCase | null): UseCaseFormState {
  const flowData = useCase?.flowData ?? {}
  return {
    name: useCase?.name ?? '',
    description: useCase?.description ?? '',
    componentIds: useCase?.components.map((component) => component.id) ?? [],
    flowIds: useCase?.flows.map((flow) => flow.id) ?? [],
    businessObjectiveIds: useCase?.businessObjectives.map((objective) => objective.id) ?? [],
    preconditions: flowData.preconditions ?? [],
    postconditions: flowData.postconditions ?? [],
    successCriteria: flowData.successCriteria ?? [],
    mainFlow: flowData.mainFlow ?? [],
    alternativeFlows: flowData.alternativeFlows ?? [],
    exceptions: flowData.exceptions ?? [],
    baseFlowData: flowData,
  }
}

export function buildUseCaseFlowData(state: UseCaseFormState): UseCaseFlowData {
  const flowData: Record<string, unknown> = { ...state.baseFlowData }
  assignList(flowData, 'preconditions', cleanStringList(state.preconditions))
  assignList(flowData, 'postconditions', cleanStringList(state.postconditions))
  assignList(flowData, 'successCriteria', cleanStringList(state.successCriteria))
  assignList(flowData, 'mainFlow', cleanSteps(state.mainFlow))
  assignList(flowData, 'alternativeFlows', cleanAlternativeFlows(state.alternativeFlows))
  assignList(flowData, 'exceptions', cleanExceptions(state.exceptions))
  return flowData as UseCaseFlowData
}

/**
 * `includeBusinessObjectives` is false when the model has none: the field is
 * then left out so the server keeps any links.
 */
export function buildUseCaseInput(state: UseCaseFormState, includeBusinessObjectives: boolean): UseCaseInput {
  const input: UseCaseInput = {
    name: state.name.trim(),
    description: state.description.trim(),
    flowData: buildUseCaseFlowData(state),
    componentIds: state.componentIds,
    flowIds: state.flowIds,
  }
  if (includeBusinessObjectives) input.businessObjectiveIds = state.businessObjectiveIds
  return input
}

// ---- Abuse case ----

export interface AbuseCaseFormState {
  name: string
  description: string
  abuserId: number | null
  useCaseIds: number[]
  componentIds: number[]
  flowIds: number[]
  preconditions: string[]
  mainFlow: FlowStep[]
  detectionOpportunities: string[]
  baseFlowData: AbuseCaseFlowData
}

export function initialAbuseCaseForm(abuseCase?: AbuseCase | null, defaultUseCaseId?: number): AbuseCaseFormState {
  const flowData = abuseCase?.flowData ?? {}
  return {
    name: abuseCase?.name ?? '',
    description: abuseCase?.description ?? '',
    abuserId: abuseCase?.abuser?.id ?? null,
    useCaseIds: abuseCase
      ? abuseCase.useCases.map((useCase) => useCase.id)
      : defaultUseCaseId !== undefined
        ? [defaultUseCaseId]
        : [],
    componentIds: abuseCase?.components.map((component) => component.id) ?? [],
    flowIds: abuseCase?.flows.map((flow) => flow.id) ?? [],
    preconditions: flowData.preconditions ?? [],
    mainFlow: flowData.mainFlow ?? [],
    detectionOpportunities: flowData.detectionOpportunities ?? [],
    baseFlowData: flowData,
  }
}

export function buildAbuseCaseFlowData(state: AbuseCaseFormState): AbuseCaseFlowData {
  const flowData: Record<string, unknown> = { ...state.baseFlowData }
  assignList(flowData, 'preconditions', cleanStringList(state.preconditions))
  assignList(flowData, 'mainFlow', cleanSteps(state.mainFlow))
  assignList(flowData, 'detectionOpportunities', cleanStringList(state.detectionOpportunities))
  return flowData as AbuseCaseFlowData
}

/** Threat links are not sent: the threat analysis view owns them. */
export function buildAbuseCaseInput(state: AbuseCaseFormState): AbuseCaseInput {
  return {
    name: state.name.trim(),
    description: state.description.trim(),
    flowData: buildAbuseCaseFlowData(state),
    abuserId: state.abuserId,
    useCaseIds: state.useCaseIds,
    componentIds: state.componentIds,
    flowIds: state.flowIds,
  }
}

// ---- Gap badges ----

export type UseCaseGap = 'not-analyzed' | 'not-linked'

export const USE_CASE_GAP_LABELS: Record<UseCaseGap, string> = {
  'not-analyzed': 'Not analyzed',
  'not-linked': 'Not linked to the diagram',
}

export function getUseCaseGaps(useCase: Pick<UseCase, 'abuseCaseCount' | 'components' | 'flows'>): UseCaseGap[] {
  const gaps: UseCaseGap[] = []
  if (useCase.abuseCaseCount === 0) gaps.push('not-analyzed')
  if (useCase.components.length === 0 && useCase.flows.length === 0) gaps.push('not-linked')
  return gaps
}

// ---- Backend errors ----

/** Flatten a DRF 400 body into messages; falls back to the error message. */
export function errorMessages(error: unknown, fallback: string): string[] {
  const messages: string[] = []
  const collect = (value: unknown) => {
    if (typeof value === 'string') messages.push(value)
    else if (Array.isArray(value)) value.forEach(collect)
    else if (value && typeof value === 'object') Object.values(value).forEach(collect)
  }
  const data = (error as { data?: unknown } | null)?.data
  if (data && typeof data === 'object') collect(data)
  if (messages.length > 0) return messages
  return [error instanceof Error && error.message ? error.message : fallback]
}
