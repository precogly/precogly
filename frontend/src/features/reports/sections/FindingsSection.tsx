import { AlertTriangle, CheckCircle, XCircle } from 'lucide-react'
import type { ReportData } from '@/features/reports/types/report'
import type { SectionDepth } from '../reportConfig'
import { deriveFindings, type FindingSeverity } from '../utils/findings'
import { ReportSection } from '../ReportSection'

interface FindingsSectionProps {
  data: ReportData
  depth: SectionDepth
}

const SEVERITY_ICONS: Record<FindingSeverity, React.ReactNode> = {
  critical: <XCircle className="h-4 w-4 text-red-500 shrink-0" />,
  high: <AlertTriangle className="h-4 w-4 text-orange-500 shrink-0" />,
  medium: <AlertTriangle className="h-4 w-4 text-yellow-500 shrink-0" />,
  info: <CheckCircle className="h-4 w-4 text-blue-500 shrink-0" />,
}

const SEVERITY_BG: Record<FindingSeverity, string> = {
  critical: 'border-red-200 bg-red-50',
  high: 'border-orange-200 bg-orange-50',
  medium: 'border-yellow-200 bg-yellow-50',
  info: 'border-blue-200 bg-blue-50',
}

export function FindingsSection({ data, depth }: FindingsSectionProps) {
  const findings = deriveFindings(data, depth)

  return (
    <ReportSection title="Findings & Action Items">
      {findings.length === 0 ? (
        <p className="text-sm text-muted-foreground">No significant findings.</p>
      ) : (
        <div className="space-y-2">
          {findings.map((finding, index) => (
            <div key={index} className={`flex items-start gap-3 p-3 rounded border ${SEVERITY_BG[finding.severity]}`}>
              {SEVERITY_ICONS[finding.severity]}
              <div>
                <div className="font-medium text-sm">{finding.title}</div>
                <div className="text-xs text-muted-foreground">{finding.detail}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </ReportSection>
  )
}
