/**
 * Page for accepting team invitations.
 * Handles both logged-in and logged-out users.
 */

import { useParams, useNavigate, Link } from 'react-router-dom'
import { useInvitationDetails, useAcceptInvitation } from '@/features/organization/api/organizations'
import { useAuth } from '@/contexts/AuthContext'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { AlertCircle, Users, Building2, CheckCircle2, Loader2 } from 'lucide-react'

export function AcceptInvitation() {
  const { token } = useParams<{ token: string }>()
  const navigate = useNavigate()
  const { user } = useAuth()
  const { data, isLoading, error } = useInvitationDetails(token ?? '')
  const acceptMutation = useAcceptInvitation()

  const handleAccept = () => {
    if (!token) return
    acceptMutation.mutate(token, {
      onSuccess: () => {
        // Redirect to dashboard after accepting
        setTimeout(() => navigate('/'), 1500)
      },
    })
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <Loader2 className="h-12 w-12 animate-spin text-primary mx-auto" />
          <p className="mt-4 text-muted-foreground">Loading invitation...</p>
        </div>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <Card className="max-w-md w-full mx-4">
          <CardContent className="pt-6">
            <div className="text-center">
              <AlertCircle className="h-12 w-12 text-destructive mx-auto" />
              <h2 className="mt-4 text-xl font-semibold">Invalid Invitation</h2>
              <p className="mt-2 text-muted-foreground">
                This invitation link has expired, been revoked, or doesn't exist.
              </p>
              <Link
                to="/login"
                className="mt-4 inline-block text-primary hover:underline"
              >
                Sign in to Precogly
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  const { invitation } = data

  // Successfully accepted
  if (acceptMutation.isSuccess) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <Card className="max-w-md w-full mx-4">
          <CardContent className="pt-6">
            <div className="text-center">
              <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto" />
              <h2 className="mt-4 text-xl font-semibold">Welcome to the team!</h2>
              <p className="mt-2 text-muted-foreground">
                You've joined {invitation.teamName}. Redirecting to dashboard...
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <Card className="max-w-md w-full mx-4">
        <CardHeader>
          <CardTitle className="text-center">Team Invitation</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Invitation details */}
          <div className="text-center space-y-4">
            <p className="text-muted-foreground">
              You've been invited to join
            </p>
            <div className="space-y-2">
              <div className="flex items-center justify-center gap-2">
                <Users className="h-5 w-5 text-muted-foreground" />
                <span className="text-lg font-semibold">{invitation.teamName}</span>
              </div>
              <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
                <Building2 className="h-4 w-4" />
                <span>{invitation.organizationName}</span>
              </div>
            </div>
            <Badge variant="secondary">Role: {invitation.role}</Badge>
          </div>

          {/* Invitation sent to */}
          <div className="text-center p-3 bg-muted/50 rounded-lg">
            <p className="text-xs text-muted-foreground">Invitation sent to</p>
            <p className="font-medium">{invitation.email}</p>
          </div>

          {/* Action based on auth state */}
          {user ? (
            <div className="space-y-3">
              <p className="text-sm text-center text-muted-foreground">
                Signed in as <strong>{user.email}</strong>
              </p>
              {user.email.toLowerCase() !== invitation.email.toLowerCase() && (
                <p className="text-sm text-amber-600 text-center">
                  Note: You're signed in with a different email than the invitation was sent to.
                </p>
              )}
              <Button
                onClick={handleAccept}
                disabled={acceptMutation.isPending}
                className="w-full"
              >
                {acceptMutation.isPending ? 'Joining...' : 'Accept Invitation'}
              </Button>
              {acceptMutation.isError && (
                <p className="text-sm text-destructive text-center">
                  {(acceptMutation.error as Error)?.message || 'Failed to accept invitation'}
                </p>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-sm text-center text-muted-foreground">
                Create an account with <strong>{invitation.email}</strong> to join this team.
              </p>
              <Button asChild className="w-full">
                <Link to={`/signup?redirect=/invite/${token}&email=${encodeURIComponent(invitation.email)}`}>
                  Create Account
                </Link>
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
