import { Card, CardContent } from '@/components/ui/card'
import { STRIDE_CONFIG, type STRIDECategory } from '@/types/domain'
import type { ReportThreatAnalysis } from '@/features/reports/types/report'
import { isStrideSummaryVisible } from '../reportConfig'
import { ReportSection } from '../ReportSection'

interface StrideSummaryProps {
  threatAnalysis: ReportThreatAnalysis
  /**
   * The model's methodologies. When given, the section renders nothing for a
   * model that does not use STRIDE (plan 11.6); the report view also leaves it
   * out of the section list, so this is the second line of defence.
   */
  methodologies?: readonly string[] | null
}

const STRIDE_ORDER: STRIDECategory[] = [
  'spoofing',
  'tampering',
  'repudiation',
  'information-disclosure',
  'denial-of-service',
  'elevation-of-privilege',
]

const STRIDE_BORDER_COLORS: Record<string, string> = {
  spoofing: 'border-l-red-500',
  tampering: 'border-l-orange-500',
  repudiation: 'border-l-yellow-500',
  'information-disclosure': 'border-l-green-500',
  'denial-of-service': 'border-l-blue-500',
  'elevation-of-privilege': 'border-l-purple-500',
  unknown: 'border-l-gray-500',
}

export function StrideSummary({ threatAnalysis, methodologies }: StrideSummaryProps) {
  if (methodologies !== undefined && !isStrideSummaryVisible(methodologies)) return null

  const { strideSummary } = threatAnalysis
  const totalThreats = Object.values(strideSummary).reduce((sum, count) => sum + count, 0)

  if (totalThreats === 0) {
    return (
      <ReportSection title="STRIDE Summary">
        <p className="text-sm text-muted-foreground">No threats identified.</p>
      </ReportSection>
    )
  }

  const categories: Array<{ key: string; label: string }> = [
    ...STRIDE_ORDER.map((category) => ({ key: category, label: STRIDE_CONFIG[category].label })),
    { key: 'unknown', label: 'Not classified' },
  ]
  const categoriesWithThreats = categories.filter((category) => (strideSummary[category.key] || 0) > 0)

  return (
    <ReportSection title="STRIDE Summary">
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {categoriesWithThreats.map((category) => (
          <Card key={category.key} className={`border-l-4 ${STRIDE_BORDER_COLORS[category.key] || ''}`}>
            <CardContent className="pt-3 pb-3">
              <div className="text-xl font-bold">{strideSummary[category.key]}</div>
              <div className="text-xs text-muted-foreground">{category.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="mt-3 text-sm text-muted-foreground">
        Total: {totalThreats} active threats across {categoriesWithThreats.length} categories
      </div>
    </ReportSection>
  )
}
