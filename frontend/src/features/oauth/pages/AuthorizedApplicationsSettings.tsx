import { useState } from 'react'
import { toast } from 'sonner'
import { Loader2, Plug } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  type AuthorizedApplication,
  useAuthorizedApplications,
  useRevokeApplication,
} from '../api/consent'

/** Lists the MCP clients that can act on the user's account, and revokes their access. */
export function AuthorizedApplicationsSettings() {
  const { data, isLoading, isError } = useAuthorizedApplications()
  const revoke = useRevokeApplication()
  // The application whose revocation is waiting for confirmation.
  const [confirming, setConfirming] = useState<AuthorizedApplication | null>(null)

  function revokeConfirmed() {
    if (!confirming) return
    const { id, name } = confirming
    revoke.mutate(id, {
      onSuccess: () => toast.success(`Revoked access for ${name}`),
      onError: () => toast.error(`Could not revoke access for ${name}`),
    })
    setConfirming(null)
  }

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
                      onClick={() => setConfirming(application)}
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

      <AlertDialog open={confirming !== null} onOpenChange={(open) => !open && setConfirming(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke access for {confirming?.name}?</AlertDialogTitle>
            <AlertDialogDescription>
              It will lose access to your account immediately, including any session it
              has open now. To use it again, you will have to approve it again.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={revokeConfirmed}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Revoke access
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}
