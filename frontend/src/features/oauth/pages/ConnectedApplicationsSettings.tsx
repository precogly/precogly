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
import { useConnectedApplications, useDisconnectApplication } from '../api/consent'

/** Lists the MCP clients that can act on the user's account, and disconnects them. */
export function ConnectedApplicationsSettings() {
  const { data, isLoading, isError } = useConnectedApplications()
  const disconnect = useDisconnectApplication()

  return (
    <Card>
      <CardHeader>
        <CardTitle>Connected applications</CardTitle>
        <CardDescription>
          MCP clients you have allowed to access your account. Disconnecting one revokes
          its access at once; it has to ask again to reconnect.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        ) : isError ? (
          <p className="text-sm text-destructive">Could not load connected applications.</p>
        ) : !data?.length ? (
          <div className="flex flex-col items-center gap-2 py-8 text-muted-foreground">
            <Plug className="h-8 w-8" />
            <p className="text-sm">No MCP clients are connected to your account.</p>
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
                      disabled={disconnect.isPending}
                      onClick={() =>
                        disconnect.mutate(application.id, {
                          onSuccess: () => toast.success(`Disconnected ${application.name}`),
                          onError: () => toast.error(`Could not disconnect ${application.name}`),
                        })
                      }
                    >
                      Disconnect
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
