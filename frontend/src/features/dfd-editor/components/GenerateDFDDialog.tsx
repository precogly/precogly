/**
 * Three-step dialog for AI-powered DFD generation from architecture diagrams.
 *
 * Step 1 (form):       Upload image + app name + description → analyze
 * Step 2 (chat):       Review extracted components + answer clarifying Qs → generate
 * Step 3 (generating): Spinner while the model produces canvas_data → insert
 *
 * Uses the same insertion path as template insertion (handleInsertTemplate) so
 * ID remapping, position offsetting, and parent relationships are handled by
 * the caller.
 */

import { useState, useCallback, useRef } from 'react'
import { Upload, X, ArrowLeft, Loader2, Sparkles } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { OwlMark } from '@/features/ai/components/OwlMark'
import { AiErrorState } from '@/features/ai/components/AiErrorState'
import {
  useAnalyzeImage,
  useGenerateDfd,
  type AnalysisResult,
  type QuestionAnswer,
} from '../api/generate-dfd'
import type { DiagramNode, DiagramEdge } from '../types'

type Step = 'form' | 'chat' | 'generating'

interface GenerateDFDDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string | undefined
  onInsert: (nodes: DiagramNode[], edges: DiagramEdge[]) => void
}

const ACCEPTED_TYPES = ['image/jpeg', 'image/png', 'image/webp']
const MAX_SIZE_MB = 10

export function GenerateDFDDialog({
  open,
  onOpenChange,
  threatModelId,
  onInsert,
}: GenerateDFDDialogProps) {
  // Step state machine
  const [step, setStep] = useState<Step>('form')

  // Form state (step 1)
  const [appName, setAppName] = useState('')
  const [appDescription, setAppDescription] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<string | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Analysis state (step 2)
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [answers, setAnswers] = useState<QuestionAnswer[]>([])

  // Mutations
  const analyzeMutation = useAnalyzeImage()
  const generateMutation = useGenerateDfd()

  // --- File handling ---

  const validateFile = useCallback((file: File): string | null => {
    if (!ACCEPTED_TYPES.includes(file.type)) {
      return 'Only JPEG, PNG, and WebP images are accepted'
    }
    if (file.size > MAX_SIZE_MB * 1024 * 1024) {
      return `Image must be smaller than ${MAX_SIZE_MB} MB`
    }
    return null
  }, [])

  const handleFileSelect = useCallback(
    (file: File) => {
      const error = validateFile(file)
      if (error) {
        setFileError(error)
        return
      }
      setFileError(null)
      setSelectedFile(file)
      const reader = new FileReader()
      reader.onloadend = () => setPreview(reader.result as string)
      reader.readAsDataURL(file)
    },
    [validateFile]
  )

  const handleFileInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (file) handleFileSelect(file)
    },
    [handleFileSelect]
  )

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback(() => {
    setIsDragging(false)
  }, [])

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setIsDragging(false)
      const file = e.dataTransfer.files[0]
      if (file) handleFileSelect(file)
    },
    [handleFileSelect]
  )

  const handleClearFile = useCallback(() => {
    setSelectedFile(null)
    setPreview(null)
    setFileError(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }, [])

  // --- Step transitions ---

  const handleAnalyze = useCallback(() => {
    if (!selectedFile || !appName.trim() || !threatModelId) return

    analyzeMutation.mutate(
      {
        image: selectedFile,
        appName: appName.trim(),
        appDescription: appDescription.trim(),
        threatModelId,
      },
      {
        onSuccess: (result) => {
          setAnalysis(result)
          // Pre-fill answer slots for each question.
          setAnswers(
            (result.questions || []).map((q) => ({ question: q, answer: '' }))
          )
          setStep('chat')
        },
      }
    )
  }, [selectedFile, appName, appDescription, threatModelId, analyzeMutation])

  // --- Reset ---

  const resetState = useCallback(() => {
    setStep('form')
    setAppName('')
    setAppDescription('')
    setSelectedFile(null)
    setPreview(null)
    setFileError(null)
    setIsDragging(false)
    setAnalysis(null)
    setAnswers([])
    analyzeMutation.reset()
    generateMutation.reset()
  }, [analyzeMutation, generateMutation])

  const handleOpenChange = useCallback(
    (nextOpen: boolean) => {
      if (!nextOpen) resetState()
      onOpenChange(nextOpen)
    },
    [onOpenChange, resetState]
  )

  const handleGenerate = useCallback(() => {
    if (!analysis || !threatModelId) return

    setStep('generating')
    generateMutation.mutate(
      {
        threatModelId,
        analysis,
        answers: answers.filter((a) => a.answer.trim()),
      },
      {
        onSuccess: (result) => {
          onInsert(
            result.nodes as unknown as DiagramNode[],
            result.edges as unknown as DiagramEdge[]
          )
          resetState()
          onOpenChange(false)
        },
        onError: () => {
          // Stay on generating step so AiErrorState can show with retry.
          setStep('generating')
        },
      }
    )
  }, [analysis, answers, threatModelId, generateMutation, onInsert, onOpenChange, resetState])

  const handleRetryGenerate = useCallback(() => {
    handleGenerate()
  }, [handleGenerate])

  // --- Answer updates ---

  const updateAnswer = useCallback((index: number, value: string) => {
    setAnswers((prev) =>
      prev.map((a, i) => (i === index ? { ...a, answer: value } : a))
    )
  }, [])

  // --- Node type badge color ---

  const typeBadgeVariant = (
    type: string
  ): 'default' | 'secondary' | 'outline' | 'destructive' => {
    switch (type) {
      case 'process':
        return 'default'
      case 'datastore':
        return 'secondary'
      default:
        return 'outline'
    }
  }

  // --- Render ---

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <OwlMark className="h-5 w-5" />
            Generate DFD with AI
          </DialogTitle>
          <DialogDescription>
            Upload an architecture diagram and let AI create a Data Flow Diagram for you.
          </DialogDescription>
        </DialogHeader>

        {/* Step indicators */}
        <div className="flex items-center gap-2 mb-4">
          <Badge variant={step === 'form' ? 'default' : 'secondary'}>
            1. Upload
          </Badge>
          <Badge
            variant={
              step === 'chat'
                ? 'default'
                : step === 'generating'
                ? 'secondary'
                : 'outline'
            }
          >
            2. Review
          </Badge>
          <Badge variant={step === 'generating' ? 'default' : 'outline'}>
            3. Generate
          </Badge>
        </div>

        {/* Step 1: Form */}
        {step === 'form' && (
          <div className="space-y-4">
            {/* App name */}
            <div className="space-y-2">
              <Label htmlFor="app-name">Application Name *</Label>
              <Input
                id="app-name"
                value={appName}
                onChange={(e) => setAppName(e.target.value)}
                placeholder="e.g. Customer Portal"
              />
            </div>

            {/* Description */}
            <div className="space-y-2">
              <Label htmlFor="app-desc">Description (optional)</Label>
              <Textarea
                id="app-desc"
                value={appDescription}
                onChange={(e) => setAppDescription(e.target.value)}
                placeholder="Brief context about the application, its purpose, and key integrations..."
                rows={3}
              />
            </div>

            {/* Image upload */}
            <div className="space-y-2">
              <Label>Architecture Diagram *</Label>
              {!selectedFile ? (
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
                    isDragging
                      ? 'border-primary bg-primary/5'
                      : 'border-muted-foreground/25 hover:border-muted-foreground/50'
                  }`}
                >
                  <Upload className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground mb-2">
                    Drag and drop an architecture diagram, or click to select
                  </p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept={ACCEPTED_TYPES.join(',')}
                    onChange={handleFileInputChange}
                    className="hidden"
                    id="dfd-image-upload"
                  />
                  <label htmlFor="dfd-image-upload">
                    <Button variant="outline" size="sm" asChild>
                      <span>Select Image</span>
                    </Button>
                  </label>
                  <p className="text-xs text-muted-foreground mt-2">
                    JPEG, PNG, or WebP &middot; Max {MAX_SIZE_MB} MB
                  </p>
                </div>
              ) : (
                <div className="relative border rounded-lg overflow-hidden">
                  {preview && (
                    <img
                      src={preview}
                      alt="Architecture diagram preview"
                      className="w-full h-48 object-contain bg-muted"
                    />
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="absolute top-2 right-2 bg-background/80"
                    onClick={handleClearFile}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                  <p className="text-xs text-muted-foreground p-2">
                    {selectedFile.name}
                  </p>
                </div>
              )}
              {fileError && (
                <p className="text-sm text-destructive">{fileError}</p>
              )}
            </div>

            {/* Analyze error */}
            {analyzeMutation.isError && (
              <AiErrorState
                error={analyzeMutation.error}
                fallbackMessage="Something went wrong analyzing the diagram."
                onRetry={handleAnalyze}
              />
            )}

            {/* Actions */}
            <div className="flex justify-end gap-2 pt-2">
              <Button
                variant="outline"
                onClick={() => handleOpenChange(false)}
              >
                Cancel
              </Button>
              <Button
                onClick={handleAnalyze}
                disabled={
                  !selectedFile ||
                  !appName.trim() ||
                  analyzeMutation.isPending
                }
              >
                {analyzeMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Sparkles className="h-4 w-4 mr-2" />
                    Analyze Diagram
                  </>
                )}
              </Button>
            </div>
          </div>
        )}

        {/* Step 2: Review & Clarify */}
        {step === 'chat' && analysis && (
          <div className="space-y-4">
            {/* Extracted components */}
            <div>
              <h3 className="text-sm font-medium mb-2">
                Extracted Components ({analysis.components.length})
              </h3>
              <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto">
                {analysis.components.map((comp, index) => (
                  <div
                    key={index}
                    className="flex items-start gap-2 p-2 border rounded-md text-sm"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="font-medium truncate">
                          {comp.name}
                        </span>
                        <Badge
                          variant={typeBadgeVariant(comp.type)}
                          className="text-[10px] px-1 py-0 shrink-0"
                        >
                          {comp.type}
                        </Badge>
                      </div>
                      {comp.technology && (
                        <p className="text-xs text-muted-foreground truncate">
                          {comp.technology}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Summary stats */}
            <div className="flex gap-4 text-sm text-muted-foreground">
              <span>{analysis.flows?.length ?? 0} flows</span>
              <span>{analysis.zones?.length ?? 0} zones</span>
              {analysis.systemScope?.name && (
                <span>Scope: {analysis.systemScope.name}</span>
              )}
            </div>

            {/* Clarifying questions */}
            {answers.length > 0 && (
              <div className="space-y-3">
                <h3 className="text-sm font-medium">
                  Clarifying Questions (optional)
                </h3>
                {answers.map((qa, index) => (
                  <div key={index} className="space-y-1">
                    <Label className="text-sm text-muted-foreground">
                      {qa.question}
                    </Label>
                    <Textarea
                      value={qa.answer}
                      onChange={(e) => updateAnswer(index, e.target.value)}
                      placeholder="Skip or provide details..."
                      rows={2}
                    />
                  </div>
                ))}
              </div>
            )}

            {/* Actions */}
            <div className="flex justify-between pt-2">
              <Button
                variant="ghost"
                onClick={() => setStep('form')}
              >
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back
              </Button>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => handleOpenChange(false)}
                >
                  Cancel
                </Button>
                <Button onClick={handleGenerate}>
                  <Sparkles className="h-4 w-4 mr-2" />
                  Generate DFD
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* Step 3: Generating */}
        {step === 'generating' && (
          <div className="py-8">
            {generateMutation.isError ? (
              <AiErrorState
                error={generateMutation.error}
                fallbackMessage="Something went wrong generating the DFD."
                onRetry={handleRetryGenerate}
              />
            ) : (
              <div className="flex flex-col items-center gap-4 text-center">
                <Loader2 className="h-8 w-8 animate-spin text-primary" />
                <div>
                  <p className="font-medium">
                    Generating your Data Flow Diagram...
                  </p>
                  <p className="text-sm text-muted-foreground mt-1">
                    This may take a moment while the AI builds the layout.
                  </p>
                </div>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
