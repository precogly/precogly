/**
 * Organization settings page — editable.
 */

import { useState, useEffect } from 'react'
import { useWorkspace } from '@/contexts/WorkspaceContext'
import { useOrganization, useUpdateOrganization } from '@/features/organization/api/organizations'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Loader2, Check, AlertCircle } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'

export function OrganizationSettings() {
  const { currentOrganization, isLoading, refresh, isSecurityTeam } = useWorkspace()
  // The workspace holds list items, which omit domain. The form reads the
  // detail endpoint so it shows the same fields the PATCH writes.
  const {
    data: organization,
    isLoading: organizationLoading,
    isError: organizationError,
  } = useOrganization(currentOrganization?.id ?? 0)
  const updateOrgMutation = useUpdateOrganization()

  const [name, setName] = useState('')
  const [domain, setDomain] = useState('')
  const [saveSuccess, setSaveSuccess] = useState(false)

  // Sync form state when org loads
  useEffect(() => {
    if (organization) {
      setName(organization.name)
      setDomain(organization.domain || '')
    }
  }, [organization])

  if (isLoading || organizationLoading) {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-64 mt-2" />
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-10 w-full max-w-md" />
            </div>
            <div className="space-y-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-10 w-full max-w-md" />
            </div>
            <Skeleton className="h-10 w-28 mt-2" />
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!currentOrganization) {
    return (
      <div className="space-y-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <AlertCircle className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-lg font-medium">No organization selected</p>
            <p className="text-sm text-muted-foreground mt-1">
              Select an organization from the workspace switcher to manage its settings.
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (organizationError || !organization) {
    return (
      <div className="space-y-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <AlertCircle className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-lg font-medium">Could not load organization settings</p>
            <p className="text-sm text-muted-foreground mt-1">
              Refresh the page to try again.
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  const hasChanges =
    name !== organization.name ||
    domain !== (organization.domain || '')

  const handleSave = () => {
    setSaveSuccess(false)
    updateOrgMutation.mutate(
      {
        id: organization.id,
        data: { name, domain },
      },
      {
        onSuccess: () => {
          setSaveSuccess(true)
          refresh()
        },
      }
    )
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Organization Details</CardTitle>
          <CardDescription>
            Update your organization settings.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="org-name">Organization Name</Label>
            <Input
              id="org-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="max-w-md"
              readOnly={!isSecurityTeam}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="org-domain">Domain</Label>
            <Input
              id="org-domain"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className="max-w-md"
              readOnly={!isSecurityTeam}
            />
          </div>

          {isSecurityTeam && (
          <div className="flex items-center gap-3 pt-2">
            <Button
              onClick={handleSave}
              disabled={!hasChanges || updateOrgMutation.isPending}
            >
              {updateOrgMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Save Changes
            </Button>
            {saveSuccess && (
              <span className="text-sm text-green-600 flex items-center gap-1">
                <Check className="h-4 w-4" />
                Saved
              </span>
            )}
          </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
