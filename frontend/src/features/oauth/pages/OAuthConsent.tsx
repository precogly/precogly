import { useState } from 'react'
import { Navigate, useLocation, useSearchParams } from 'react-router-dom'
import { AlertCircle, AlertTriangle, Loader2, Shield } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { ApiError } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useDecision, usePendingAuthorization } from '../api/consent'

/**
 * Asks the signed-in user whether an MCP client may act on their Precogly account.
 *
 * Allowing asks for the password again: a JWT proves only that the account signed in
 * within the last hour, not that the person at the keyboard knows the password.
 */
export function OAuthConsent() {
  const [searchParams] = useSearchParams()
  const location = useLocation()
  // The handle `/o/authorize/` redirects here with.
  const handle = searchParams.get('id') ?? ''
  const { isAuthenticated, isLoading: authLoading } = useAuth()
  const pending = usePendingAuthorization(handle, isAuthenticated)
  const decision = useDecision(handle)
  const [password, setPassword] = useState('')

  if (authLoading) {
    return <Centered><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></Centered>
  }
  if (!isAuthenticated) {
    const back = `${location.pathname}${location.search}`
    return <Navigate to={`/login?redirect=${encodeURIComponent(back)}`} replace />
  }
  if (pending.isLoading) {
    return <Centered><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></Centered>
  }
  if (pending.isError || !pending.data) {
    return (
      <Centered>
        <Card className="w-full max-w-md">
          <CardContent className="pt-6 text-center">
            <AlertCircle className="h-12 w-12 text-destructive mx-auto" />
            <h2 className="mt-4 text-xl font-semibold">This request can no longer be used</h2>
            <p className="mt-2 text-muted-foreground">
              It has expired or was already answered. Start again from your MCP client.
            </p>
          </CardContent>
        </Card>
      </Centered>
    )
  }

  const { clientName, scopes, redirectUri, loopbackRedirect } = pending.data

  function decide(allow: boolean) {
    decision.mutate(allow ? { allow, password } : { allow }, {
      onSuccess: ({ redirectUrl }) => window.location.assign(redirectUrl),
    })
  }

  const passwordError =
    decision.error instanceof ApiError && decision.error.status === 400
      ? 'That password is incorrect.'
      : null
  const requestGone = decision.error instanceof ApiError && decision.error.status === 404

  return (
    <Centered>
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="flex items-center gap-2 text-primary">
              <Shield className="h-8 w-8" />
              <span className="text-2xl font-bold">Precogly</span>
            </div>
          </div>
          {/* The registering client chose this name; React renders it as text. */}
          <CardTitle>Allow {clientName} to access your account?</CardTitle>
          <CardDescription>It will be able to:</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <ul className="space-y-1 text-sm">
            {scopes.map((scope) => (
              <li key={scope.name}>{scope.description}</li>
            ))}
          </ul>

          <p className="text-xs text-muted-foreground break-all">
            You will be sent back to <span className="font-mono">{redirectUri}</span>
          </p>

          {loopbackRedirect && (
            <div className="flex gap-2 p-3 text-sm bg-amber-500/10 rounded-md">
              <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-amber-600" />
              <span>
                This client runs on your computer. Allow it only if you started it just now.
              </span>
            </div>
          )}

          {requestGone && (
            <div className="p-3 text-sm text-destructive bg-destructive/10 rounded-md">
              This request can no longer be used. Start again from your MCP client.
            </div>
          )}

          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              decide(true)
            }}
          >
            <div className="space-y-2">
              <Label htmlFor="password">Confirm your password to allow</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
              />
              {passwordError && <p className="text-sm text-destructive">{passwordError}</p>}
            </div>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                className="flex-1"
                disabled={decision.isPending}
                onClick={() => decide(false)}
              >
                Deny
              </Button>
              <Button type="submit" className="flex-1" disabled={decision.isPending}>
                {decision.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Allow
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </Centered>
  )
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-muted/30 p-4">
      {children}
    </div>
  )
}
