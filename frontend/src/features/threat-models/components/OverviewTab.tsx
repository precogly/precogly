/**
 * The Overview tab: a vertical list of sections, collapsed to a header row
 * unless noted. Top to bottom: diagrams with "+ New DFD" and the completion
 * checklist (open), the review row, three buttons that open the System
 * (Details and Context tabs), Business objectives and Use cases dialogs,
 * Connections, and Reference images (open when the model has one).
 */

import { useState } from 'react'
import { Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  BlueprintSwitcher,
  BusinessObjectivesDialog,
  CompletionStatusCard,
  DFDCarousel,
  OverviewDetailButtons,
  OverviewSection,
  ReferenceImageGallery,
  ReferenceImageUploader,
  RelationshipCards,
  ReviewCard,
  UseCasesDialog,
  countLabel,
  showsBlueprintChoice,
} from '@/features/threat-models/components/workspace'
import type { Diagram } from '@/types'
import type { Blueprint, ReferenceImage, ThreatModel } from '@/features/threat-models/types/core'
import type { CompletionStatus, ProgressChecklistItem } from '@/features/dfd-editor/types/threat-analysis'

interface OverviewTabProps {
  threatModel: ThreatModel
  /** Every blueprint of the model. */
  blueprints: Blueprint[]
  selectedBlueprintId: number | null
  /** The diagrams of the switcher's blueprint (or all, with one blueprint). */
  diagrams: Diagram[]
  progressChecklist: ProgressChecklistItem[]
  completionStatus?: CompletionStatus
  selectedDiagramId: string | null
  referenceImages: ReferenceImage[]
  isCreatingDiagram: boolean
  isUploadingImage: boolean
  isSecurityTeam: boolean
  onSelectBlueprint: (blueprintId: number) => void
  onAddBlueprint: () => void
  onManageBlueprints: () => void
  onSelectDiagram: (id: string | null) => void
  onEditDiagram: (diagramId: string) => void
  onCreateDiagram: () => void
  onUploadImage: (file: File, description?: string) => Promise<void>
  onDeleteImage: (imageId: number) => Promise<void>
  onImageClick: (index: number) => void
  onManageThreatModels: () => void
  onManagePacks: () => void
  onManagePeople: () => void
  /** Opens the System dialog (System Details and System context) on a tab. */
  onOpenSystem: (tab: 'details' | 'context') => void
}

export function OverviewTab({
  threatModel,
  blueprints,
  selectedBlueprintId,
  diagrams,
  progressChecklist,
  completionStatus,
  selectedDiagramId,
  referenceImages,
  isCreatingDiagram,
  isUploadingImage,
  isSecurityTeam,
  onSelectBlueprint,
  onAddBlueprint,
  onManageBlueprints,
  onSelectDiagram,
  onEditDiagram,
  onCreateDiagram,
  onUploadImage,
  onDeleteImage,
  onImageClick,
  onManageThreatModels,
  onManagePacks,
  onManagePeople,
  onOpenSystem,
}: OverviewTabProps) {
  const threatModelId = threatModel.id

  const [businessObjectivesOpen, setBusinessObjectivesOpen] = useState(false)
  const [useCasesOpen, setUseCasesOpen] = useState(false)
  // Reference images start open when the model has one. The images load after
  // the first render, so the section follows them until someone toggles it.
  const [referenceImagesOpenChoice, setReferenceImagesOpenChoice] = useState<boolean | null>(null)
  const referenceImagesOpen = referenceImagesOpenChoice ?? referenceImages.length > 0

  return (
    <div className="space-y-4">
      {/* Diagrams and completion: the page's call to action is a new DFD. */}
      <OverviewSection title="Diagrams and completion" defaultOpen testId="overview-diagrams-section">
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,620px)]">
          <div className="min-w-0 space-y-3">
            {showsBlueprintChoice(blueprints) && (
              <BlueprintSwitcher
                blueprints={blueprints}
                selectedBlueprintId={selectedBlueprintId}
                onSelect={onSelectBlueprint}
                onAddBlueprint={onAddBlueprint}
                onManageBlueprints={onManageBlueprints}
              />
            )}
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
              <div className="rounded-lg bg-muted/30 p-8 text-center">
                <p className="mb-4 text-sm text-muted-foreground">
                  No DFDs created yet. Create a data flow diagram to start threat modeling.
                </p>
                <Button onClick={onCreateDiagram} disabled={isCreatingDiagram} className="gap-2">
                  <Plus className="h-4 w-4" />
                  {isCreatingDiagram ? 'Creating...' : 'New DFD'}
                </Button>
              </div>
            )}
          </div>
          {/* A rule between the diagrams and the checklist: beside them on wide screens, above on narrow ones. */}
          <div className="min-w-0 border-t pt-4 xl:border-t-0 xl:border-l xl:pt-0 xl:pl-6">
            <h3 className="text-sm font-medium">Completion Status</h3>
            <p className="mb-3 text-xs text-muted-foreground">Did We Do a Good Job?</p>
            <CompletionStatusCard completionStatus={completionStatus} progressChecklist={progressChecklist} />
          </div>
        </div>
      </OverviewSection>

      <ReviewCard threatModelId={threatModelId} threatModelName={threatModel.name} isSecurityTeam={isSecurityTeam} />

      <OverviewDetailButtons
        threatModel={threatModel}
        onOpenSystem={() => onOpenSystem('details')}
        onOpenBusinessObjectives={() => setBusinessObjectivesOpen(true)}
        onOpenUseCases={() => setUseCasesOpen(true)}
      />

      <OverviewSection
        title="Connections"
        summary="Related models, library packs, team members, blueprints"
        testId="overview-connections-section"
      >
        <RelationshipCards
          blueprintCount={blueprints.length}
          onManageThreatModels={onManageThreatModels}
          onManagePacks={onManagePacks}
          onManagePeople={onManagePeople}
          onManageBlueprints={onManageBlueprints}
        />
      </OverviewSection>

      <OverviewSection
        title="Reference images"
        summary={referenceImages.length > 0 ? countLabel(referenceImages.length, 'image') : undefined}
        open={referenceImagesOpen}
        onOpenChange={setReferenceImagesOpenChoice}
        testId="overview-reference-images-section"
      >
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Upload diagrams, whiteboard photos, or architecture screenshots for reference
          </p>
          <ReferenceImageUploader onUpload={onUploadImage} isUploading={isUploadingImage} />
          {referenceImages.length > 0 && (
            <div className="pt-4">
              <ReferenceImageGallery images={referenceImages} onImageClick={onImageClick} onDelete={onDeleteImage} />
            </div>
          )}
        </div>
      </OverviewSection>

      <BusinessObjectivesDialog
        open={businessObjectivesOpen}
        onOpenChange={setBusinessObjectivesOpen}
        threatModelId={threatModelId}
      />
      <UseCasesDialog open={useCasesOpen} onOpenChange={setUseCasesOpen} threatModelId={threatModelId} />
    </div>
  )
}
