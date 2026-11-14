from django.conf import settings
from django.http import HttpResponseRedirect
from django.views.generic import TemplateView
from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import get_application_model
from oauth2_provider.oauth2_validators import is_valid_resource_uri
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views.mixins import OAuthLibMixin
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error

from apps.oauth.models import PendingAuthorization


class AuthorizeView(OAuthLibMixin, TemplateView):
    """Stores a validated authorization request and sends the browser to the consent page.

    django-oauth-toolkit's `AuthorizationView` requires a Django session at this point;
    this view requires none, because the user signs in on the consent page instead.
    It drops the toolkit's `skip_authorization`, `approval_prompt=auto` and
    `prompt=login`, which all need a signed-in user here. Dynamic registration never
    sets `skip_authorization`, and `REQUEST_APPROVAL_PROMPT` is left at `force`.
    """

    # Renders errors raised before a valid `redirect_uri` is known. Errors after that
    # go back to the client.
    template_name = "oauth2_provider/authorize.html"

    def get(self, request, *args, **kwargs):
        try:
            scopes, credentials = self.validate_authorization_request(request)
        except OAuthToolkitError as error:
            return self.error_response(error, allowed_schemes=None)

        application = get_application_model().objects.get(
            client_id=credentials["client_id"]
        )
        resource = request.GET.getlist("resource")
        for resource_uri in resource:
            if not is_valid_resource_uri(resource_uri):
                error = OAuthToolkitError(
                    error=CustomOAuth2Error(
                        error="invalid_target",
                        description=(
                            f"The resource '{resource_uri}' is not a valid resource "
                            "indicator: it must be an absolute URI with a scheme and host."
                        ),
                        state=credentials.get("state"),
                    ),
                    redirect_uri=credentials["redirect_uri"],
                )
                return self.error_response(
                    error, allowed_schemes=application.get_allowed_schemes()
                )

        pending = PendingAuthorization.from_validated(scopes, credentials, resource)
        pending.save()
        return HttpResponseRedirect(
            f"{settings.FRONTEND_URL}/oauth/consent?id={pending.id}"
        )

    def error_response(self, error, allowed_schemes):
        redirect, response = super().error_response(error)
        if redirect:
            return OAuth2ResponseRedirect(
                response["url"],
                allowed_schemes or oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES,
            )
        return self.render_to_response(response, status=response["error"].status_code)
