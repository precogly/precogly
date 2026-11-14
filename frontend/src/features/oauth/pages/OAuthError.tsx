import { useSearchParams } from 'react-router-dom'
import { AlertCircle } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'

/**
 * Shows an authorization error that could not be sent back to the MCP client, because
 * the request named no client or redirect URI that Precogly trusts.
 */
export function OAuthError() {
  const [searchParams] = useSearchParams()
  // Both values come from the query string, so a crafted link controls them. React
  // renders them as text, so they cannot inject markup. They appear in small print under
  // the fixed message, so a crafted link can add text but cannot replace the message.
  const code = searchParams.get('error')
  const description = searchParams.get('error_description')

  return (
    <div className="min-h-screen flex items-center justify-center bg-muted/30 p-4">
      <Card className="w-full max-w-md">
        <CardContent className="pt-6 text-center">
          <AlertCircle className="h-12 w-12 text-destructive mx-auto" />
          <h2 className="mt-4 text-xl font-semibold">This connection request isn't valid</h2>
          <p className="mt-2 text-muted-foreground">
            Your MCP client sent a request Precogly can't accept, so it can't be connected.
            Remove the server from the client and add it again, or ask whoever set the
            client up.
          </p>
          {(code || description) && (
            <p className="mt-4 text-xs text-muted-foreground break-words">
              {description}
              {code && <span className="font-mono"> ({code})</span>}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
