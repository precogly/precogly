import { useState } from 'react'
import { toast } from 'sonner'
import { Check, Loader2, Plug } from 'lucide-react'
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
          <>
            <p className="text-sm text-muted-foreground mb-2">
              You have granted {data.length} {data.length === 1 ? 'application' : 'applications'}{' '}
              access to your account.
            </p>
            <ul className="divide-y">
              {data.map((application) => (
                <li key={application.id} className="flex items-start justify-between gap-4 py-4">
                  <div className="space-y-1">
                    {/* Chosen by the registering client; React renders it as text. */}
                    <p className="font-medium">{application.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {application.runsLocally
                        ? 'Runs on this computer'
                        : `Returns to ${application.redirectHost}`}
                      {' · '}
                      Added {new Date(application.registeredAt).toLocaleDateString()}
                    </p>
                    <ul className="pt-1 space-y-0.5">
                      {application.scopes.map((scope) => (
                        <li key={scope.name} className="flex items-center gap-1.5 text-sm">
                          <Check className="h-3.5 w-3.5 text-muted-foreground" />
                          {scope.description}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={revoke.isPending}
                    onClick={() => setConfirming(application)}
                  >
                    Revoke access
                  </Button>
                </li>
              ))}
            </ul>
          </>
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
