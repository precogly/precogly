import { toast } from 'sonner'
import { Loader2, Plug } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useAuthorizedApplications, useRevokeApplication } from '../api/consent'

/** Lists the MCP clients that can act on the user's account, and revokes their access. */
export function AuthorizedApplicationsSettings() {
  const { data, isLoading, isError } = useAuthorizedApplications()
  const revoke = useRevokeApplication()

  return (
    <Card>
      <CardHeader>
        <CardTitle>Authorized applications</CardTitle>
        <CardDescription>
          MCP clients you have allowed to act on your account. Revoking access takes effect
          immediately; the client has to ask for your permission again to reconnect.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        ) : isError ? (
          <p className="text-sm text-destructive">Could not load authorized applications.</p>
        ) : !data?.length ? (
          <div className="flex flex-col items-center gap-2 py-8 text-muted-foreground">
            <Plug className="h-8 w-8" />
            <p className="text-sm">No MCP clients have access to your account.</p>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Application</TableHead>
                <TableHead>Access</TableHead>
                <TableHead>Last authorized</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((application) => (
                <TableRow key={application.id}>
                  {/* Chosen by the registering client; React renders it as text. */}
                  <TableCell className="font-medium">{application.name}</TableCell>
                  <TableCell className="text-sm">
                    {application.scopes.map((scope) => scope.description).join('; ')}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(application.lastTokenIssuedAt).toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={revoke.isPending}
                      onClick={() =>
                        revoke.mutate(application.id, {
                          onSuccess: () =>
                            toast.success(`Revoked access for ${application.name}`),
                          onError: () =>
                            toast.error(`Could not revoke access for ${application.name}`),
                        })
                      }
                    >
                      Revoke access
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
