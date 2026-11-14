from rest_framework.permissions import BasePermission
from rest_framework_simplejwt.authentication import JWTAuthentication


class SignedInInBrowser(BasePermission):
    """Allows only requests authenticated by the React application's JWT.

    The consent API grants MCP clients access to the user's account, so an MCP client
    must not be able to call it as the user. Two paths would let one:

    - `DEFAULT_AUTHENTICATION_CLASSES` includes `OAuth2Authentication`, so an MCP access
      token authenticates any API call as its user.
    - Code mode's `execute` calls the API through `apps.core.mcp.api.dispatch`, which
      sets `_force_auth_user`. DRF then replaces the view's authentication classes with
      `ForcedAuthentication`, so listing only `JWTAuthentication` on a view does not
      keep it out.
    """

    def has_permission(self, request, view):
        # For example, a user connects Claude Code with a `read` token. Claude can start
        # a new authorization that asks for `write`, call `/o/authorize/` itself, and
        # take the handle from the redirect. Without this check it could approve that
        # request through the consent API with its `read` token, so only the password
        # on the decision would stop it granting itself `write`.
        #
        # DRF records the authentication class that accepted the request's credential.
        # Each way of calling as the user leaves a different one:
        #
        #   caller                      credential          authenticator         result
        #   --------------------------  ------------------  --------------------  ------
        #   the user's browser          JWT from the login  JWTAuthentication     200
        #   an MCP client, directly     OAuth access token  OAuth2Authentication  403
        #   an MCP client, via execute  none, forced user   ForcedAuthentication  403
        return isinstance(request.successful_authenticator, JWTAuthentication)
