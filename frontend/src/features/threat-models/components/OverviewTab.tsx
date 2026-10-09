import { Button } from '@/components/ui/button'
import {
  CompletionStatusCard,
  ReferenceImageGallery,
  ReferenceImageUploader,
  RelationshipCards,
  DFDCarousel,
  SummaryCards,
  ReviewCard,
  ModelDetailsCard,
  BusinessObjectivesCard,
  SystemContextSummary,
  UseCasesCard,
} from '@/features/threat-models/components/workspace'
import type { Diagram } from '@/types'
import type { Blueprint, ReferenceImage, ThreatModel } from '@/features/threat-models/types/core'
import type { CompletionStatus, ProgressChecklistItem } from '@/features/dfd-editor/types/threat-analysis'

interface SummaryData {
  componentSummary: {
    total: number
    processes: number
    datastores: number
    humanActors: number
    systemActors: number
    trustZones: number
  }
  threatSummary: {
    total: number
    exposed: number
    addressable: number
    mitigated: number
  }
  countermeasureSummary: {
    total: number
    platform: number
    verified: number
    gap: number
    planned: number
    waived: number
  }
}

interface OverviewTabProps {
  threatModel: ThreatModel
  /** Every blueprint of the model; the summary cards aggregate across them (plan 11.5). */
  blueprints: Blueprint[]
  /** The diagrams of the switcher's blueprint (or all, with one blueprint). */
  diagrams: Diagram[]
  progressChecklist: ProgressChecklistItem[]
  completionStatus?: CompletionStatus
  summaries: SummaryData
  selectedDiagramId: string | null
  referenceImages: ReferenceImage[]
  isCreatingDiagram: boolean
  isUploadingImage: boolean
  isSecurityTeam: boolean
  onSelectDiagram: (id: string | null) => void
  onEditDiagram: (diagramId: string) => void
  onCreateDiagram: () => void
  onUploadImage: (file: File, description?: string) => Promise<void>
  onDeleteImage: (imageId: number) => Promise<void>
  onImageClick: (index: number) => void
  onManageThreatModels: () => void
  onManagePacks: () => void
  onManagePeople: () => void
  onEditSystemContext: () => void
  onNavigateToThreats: () => void
}

export function OverviewTab({
  threatModel,
  blueprints,
  diagrams,
  progressChecklist,
  completionStatus,
  summaries,
  selectedDiagramId,
  referenceImages,
  isCreatingDiagram,
  isUploadingImage,
  isSecurityTeam,
  onSelectDiagram,
  onEditDiagram,
  onCreateDiagram,
  onUploadImage,
  onDeleteImage,
  onImageClick,
  onManageThreatModels,
  onManagePacks,
  onManagePeople,
  onEditSystemContext,
  onNavigateToThreats,
}: OverviewTabProps) {
  const threatModelId = threatModel.id

  return (
    <div className="space-y-6">
      {/* Completion Status + Review */}
      <div className="grid grid-cols-2 gap-6">
        <div className="border rounded-lg p-4">
          <h3 className="text-sm font-medium">Completion Status</h3>
          <p className="text-xs text-muted-foreground mb-3">Did We Do a Good Job?</p>
          <CompletionStatusCard
            completionStatus={completionStatus}
            progressChecklist={progressChecklist}
          />
        </div>
        <ReviewCard
          threatModelId={threatModelId}
          threatModelName={threatModel.name}
          isSecurityTeam={isSecurityTeam}
        />
      </div>

      {/* Summary Cards: counts across every blueprint */}
      <SummaryCards
        components={summaries.componentSummary}
        threats={summaries.threatSummary}
        countermeasures={summaries.countermeasureSummary}
        blueprintCount={blueprints.length}
        onComponentsClick={onNavigateToThreats}
        onThreatsClick={onNavigateToThreats}
        onCountermeasuresClick={onNavigateToThreats}
      />

      {/* Details + Business objectives */}
      <div className="grid grid-cols-2 gap-6">
        <ModelDetailsCard
          threatModel={threatModel}
          blueprints={blueprints}
          onEditDescription={onEditSystemContext}
        />
        <div className="space-y-6">
          <BusinessObjectivesCard threatModelId={threatModelId} />
          <SystemContextSummary threatModelId={threatModelId} onOpen={onEditSystemContext} />
          <RelationshipCards
            onManageThreatModels={onManageThreatModels}
            onManagePacks={onManagePacks}
            onManagePeople={onManagePeople}
          />
        </div>
      </div>

      <UseCasesCard threatModelId={threatModelId} />

      {/* DFD Carousel */}
      {diagrams.length > 0 ? (
        <DFDCarousel
          diagrams={diagrams}
          selectedDiagramId={selectedDiagramId}
          onSelectDiagram={onSelectDiagram}
          onEditDiagram={onEditDiagram}
          onCreateDiagram={onCreateDiagram}
          isCreating={isCreatingDiagram}
        />
      ) : (
        <div className="border rounded-lg p-12 text-center">
          <p className="text-muted-foreground mb-4">
            No DFDs created yet. Create a data flow diagram to start threat modeling.
          </p>
          <Button onClick={onCreateDiagram} disabled={isCreatingDiagram}>
            {isCreatingDiagram ? 'Creating...' : 'Create First DFD'}
          </Button>
        </div>
      )}

      {/* Reference Images */}
      <div className="border rounded-lg p-6 space-y-4">
        <h3 className="text-lg font-semibold">Reference Images</h3>
        <p className="text-sm text-muted-foreground">
          Upload diagrams, whiteboard photos, or architecture screenshots for reference
        </p>

        <ReferenceImageUploader
          onUpload={onUploadImage}
          isUploading={isUploadingImage}
        />

        {referenceImages.length > 0 && (
          <div className="pt-4">
            <ReferenceImageGallery
              images={referenceImages}
              onImageClick={onImageClick}
              onDelete={onDeleteImage}
            />
          </div>
        )}
      </div>
    </div>
  )
}
