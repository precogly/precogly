import { useRef, useState } from 'react'
import { toast } from 'sonner'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Button } from '@/components/ui/button'
import { Loader2, BarChart3, Code, Shield, FileText, Download, ChevronDown } from 'lucide-react'
import { useReport } from '@/features/reports/api/reports'
import type { ReportType, ReportData } from '@/features/reports/types/report'
import { getSectionsForType, type SectionDepth } from './reportConfig'
import { ExecutiveSummary } from './sections/ExecutiveSummary'
import { ScopeSection } from './sections/ScopeSection'
import { ReviewSection } from './sections/ReviewSection'
import { BusinessObjectivesSection } from './sections/BusinessObjectivesSection'
import { ArchitectureSection } from './sections/ArchitectureSection'
import { DataAssetsSection } from './sections/DataAssetsSection'
import { ComponentInventory } from './sections/ComponentInventory'
import { StrideSummary } from './sections/StrideSummary'
import { ThreatAnalysisSection } from './sections/ThreatAnalysisSection'
import { TriagedThreatsSection } from './sections/TriagedThreatsSection'
import { CountermeasureSection } from './sections/CountermeasureSection'
import { RiskSection } from './sections/RiskSection'
import { ComplianceSection } from './sections/ComplianceSection'
import { CrossFrameworkMappingsSection } from './sections/CrossFrameworkMappingsSection'
import { ComplianceMatrixSection } from './sections/ComplianceMatrixSection'
import { AssumptionsReviewSection } from './sections/AssumptionsReviewSection'
import { FindingsSection } from './sections/FindingsSection'
import { ProgressChecklistSection } from './sections/ProgressChecklistSection'
import { ComplianceDriftBanner } from '@/features/compliance/components/ComplianceDriftBanner'
import {
  exportThreatsCSV,
  exportCountermeasuresCSV,
  exportRisksCSV,
  exportAssumptionsCSV,
  exportComplianceCSV,
  exportComplianceMatrixCSV,
} from './utils/csvExport'
import { exportWordDoc } from './utils/wordExport'
import { ReadOnlyDFDViewer, type ReadOnlyDFDViewerHandle } from '@/components/shared/ReadOnlyDFDViewer'

interface ReportViewProps {
  threatModelId: string
}

const REPORT_TYPES: Array<{
  type: ReportType
  label: string
  description: string
  icon: React.ReactNode
}> = [
  {
    type: 'executive',
    label: 'Executive',
    description: 'High-level overview for leadership',
    icon: <BarChart3 className="h-4 w-4" />,
  },
  {
    type: 'technical',
    label: 'Technical',
    description: 'Detailed analysis for engineers',
    icon: <Code className="h-4 w-4" />,
  },
  {
    type: 'compliance',
    label: 'Compliance',
    description: 'Framework coverage and gaps',
    icon: <Shield className="h-4 w-4" />,
  },
  {
    type: 'full',
    label: 'Full',
    description: 'Complete threat model report',
    icon: <FileText className="h-4 w-4" />,
  },
]

function renderSection(sectionId: string, depth: SectionDepth, data: ReportData, threatModelId: string) {
  switch (sectionId) {
    case 'executiveSummary':
      return <ExecutiveSummary data={data} />
    case 'review':
      return <ReviewSection metadata={data.metadata} assumptions={data.scope.assumptions} depth={depth} />
    case 'scope':
      return <ScopeSection scope={data.scope} depth={depth} metadata={data.metadata} />
    case 'businessObjectives':
      return <BusinessObjectivesSection objectives={data.scope.businessObjectives} depth={depth} />
    case 'architecture':
      return <ArchitectureSection architecture={data.architecture} />
    case 'dataAssets':
      return <DataAssetsSection dataAssets={data.dataAssets} depth={depth} />
    case 'components':
      return <ComponentInventory components={data.components} dataFlows={data.flows} />
    case 'strideSummary':
      return <StrideSummary threatAnalysis={data.threatAnalysis} methodologies={data.metadata.methodologies} />
    case 'threatDetail':
      return <ThreatAnalysisSection threatAnalysis={data.threatAnalysis} />
    case 'triagedThreats':
      return <TriagedThreatsSection triagedThreats={data.threatAnalysis.triagedThreats} />
    case 'countermeasureStatus':
    case 'countermeasureDetail':
    case 'gaps':
    case 'waived':
    case 'unattached':
      return (
        <CountermeasureSection
          summary={data.countermeasureSummary}
          depth={depth}
          sectionId={sectionId}
          threats={data.threatAnalysis.threats}
        />
      )
    case 'risks':
      return <RiskSection risks={data.risks} depth={depth} />
    case 'compliance':
      return <ComplianceSection compliance={data.compliance} depth={depth} />
    case 'complianceMatrix':
      return <ComplianceMatrixSection matrix={data.complianceMatrix} threatModelId={threatModelId} />
    case 'crossFrameworkMappings':
      return <CrossFrameworkMappingsSection compliance={data.compliance} />
    case 'assumptions':
      return <AssumptionsReviewSection scope={data.scope} depth={depth} />
    case 'findings':
      return <FindingsSection data={data} depth={depth} />
    case 'progressChecklist':
      return <ProgressChecklistSection progressChecklist={data.progressChecklist} completionStatus={data.completionStatus} />
    default:
      return null
  }
}

export function ReportView({ threatModelId }: ReportViewProps) {
  const [reportType, setReportType] = useState<ReportType>('executive')
  const [isExportingWord, setIsExportingWord] = useState(false)
  const dfdViewerRefs = useRef<Record<string, ReadOnlyDFDViewerHandle | null>>({})
  const { data, isLoading, error } = useReport(threatModelId)
  const sections = getSectionsForType(reportType, { methodologies: data?.metadata.methodologies ?? [] })

  const handleWordExport = async (reportData: ReportData) => {
    setIsExportingWord(true)

    // Give each off-screen React Flow viewer time to mount, measure its nodes,
    // and apply fitView before capturing the actual rendered diagram.
    await new Promise<void>((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolve()))
    })

    try {
      const dfdImages = new Map<string, Uint8Array>()
      for (const dfd of reportData.architecture.dfds) {
        const canvasData = dfd.canvasData
        if (!canvasData?.nodes?.length) continue
        const viewer = dfdViewerRefs.current[dfd.id]
        if (!viewer) throw new Error(`DFD viewer is not ready: ${dfd.name}`)
        dfdImages.set(dfd.id, await viewer.captureImage())
      }
      await exportWordDoc(reportData, reportData.metadata.name, dfdImages)
    } finally {
      setIsExportingWord(false)
    }
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {reportType === 'compliance' && (
        <ComplianceDriftBanner threatModelId={threatModelId} />
      )}


      <div className="flex-1 overflow-y-auto p-4">
        {isLoading && (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            <span className="ml-2 text-muted-foreground">Loading report data...</span>
          </div>
        )}
        {error && (
          <div className="text-center py-12">
            <p className="text-destructive">Failed to load report data.</p>
            <p className="text-sm text-muted-foreground mt-1">
              {error instanceof Error ? error.message : 'Unknown error'}
            </p>
          </div>
        )}
        {data && (
          <div className="space-y-4 max-w-5xl mx-auto">
            {/* One row: the model's name on the left, the report type and the export menu together on the right. */}
            <div className="flex items-center gap-6">
              <h2 className="min-w-0 flex-1 truncate text-lg font-semibold" data-testid="report-title" title={data.metadata.name}>
                {data.metadata.name}
              </h2>
              <div className="flex shrink-0 items-center gap-2">
                <Select value={reportType} onValueChange={(value) => setReportType(value as ReportType)}>
                  <SelectTrigger className="h-8 w-[220px] text-sm" aria-label="Report type">
                    {/* The closed select shows the name only; the list adds each description. */}
                    <SelectValue>
                      <span className="flex items-center gap-2">
                        {REPORT_TYPES.find((rt) => rt.type === reportType)?.icon}
                        {REPORT_TYPES.find((rt) => rt.type === reportType)?.label} Report
                      </span>
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    {REPORT_TYPES.map((rt) => (
                      <SelectItem key={rt.type} value={rt.type} textValue={`${rt.label} Report`}>
                        <span className="flex items-center gap-2">
                          {rt.icon}
                          <span>
                            <span className="block text-sm">{rt.label} Report</span>
                            <span className="block text-xs text-muted-foreground">{rt.description}</span>
                          </span>
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm" className="gap-1.5">
                    <Download className="h-4 w-4" />
                    Export CSV
                    <ChevronDown className="h-3.5 w-3.5 opacity-60" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={() => exportThreatsCSV(data, data.metadata.name)}>
                    Threats
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => exportCountermeasuresCSV(data, data.metadata.name)}>
                    Countermeasures
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => exportRisksCSV(data, data.metadata.name)}>
                    Risks
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => exportAssumptionsCSV(data, data.metadata.name)}>
                    Assumptions
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => exportComplianceCSV(data, data.metadata.name)}>
                    Compliance Coverage
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => exportComplianceMatrixCSV(data, data.metadata.name)}>
                    Compliance Matrix
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={async () => {
                      try {
                        await handleWordExport(data)
                      } catch (err) {
                        toast.error(
                          err instanceof Error
                            ? "Failed to export Word report: " + err.message
                            : "Failed to export Word report"
                        )
                      }
                    }}
                  >
                    Full Report (Word)
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
              </div>
            </div>

            {isExportingWord && (
              <div
                aria-hidden="true"
                style={{
                  position: 'fixed',
                  left: '-100000px',
                  top: 0,
                  width: '1200px',
                  pointerEvents: 'none',
                }}
              >
                {data.architecture.dfds.map((dfd) => (
                  dfd.canvasData?.nodes?.length ? (
                    <ReadOnlyDFDViewer
                      key={dfd.id}
                      ref={(viewer) => { dfdViewerRefs.current[dfd.id] = viewer }}
                      canvasData={dfd.canvasData}
                      className="h-[700px] w-[1200px]"
                    />
                  ) : null
                ))}
              </div>
            )}

            {sections.map((section) => (
              <div key={section.id}>
                {renderSection(section.id, section.depth, data, threatModelId)}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
