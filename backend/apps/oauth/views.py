from urllib.parse import urlsplit

from django.conf import settings
from django.db import transaction
from django.http import HttpResponseRedirect
from django.utils import timezone
from django.views.generic import TemplateView
from drf_spectacular.utils import extend_schema
from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import get_application_model
from oauth2_provider.oauth2_validators import is_valid_resource_uri
from oauth2_provider.scopes import get_scopes_backend
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views.mixins import OAuthLibMixin
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.oauth.models import MAX_PASSWORD_ATTEMPTS, PendingAuthorization
from apps.oauth.permissions import SignedInInBrowser
from apps.oauth.serializers import (
    DecisionResultSerializer,
    DecisionSerializer,
    PendingAuthorizationSerializer,
)

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


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


class PendingAuthorizationView(APIView):
    """Returns a pending authorization request to the consent page, binding it to the
    first user who reads it.

    Every refusal is a 404, so the response never says whether a handle exists.
    """

    permission_classes = [IsAuthenticated, SignedInInBrowser]

    @extend_schema(responses=PendingAuthorizationSerializer)
    def get(self, request, handle):
        live = PendingAuthorization.objects.filter(
            id=handle, used=False, expires_at__gt=timezone.now()
        )
        # One conditional UPDATE, so two users reading the same handle at once cannot
        # both bind it.
        live.filter(user__isnull=True).update(user=request.user)
        pending = live.filter(user=request.user).select_related("application").first()
        if pending is None:
            raise NotFound

        descriptions = get_scopes_backend().get_all_scopes()
        return Response(
            PendingAuthorizationSerializer(
                {
                    "client_name": pending.application.name,
                    "scopes": [
                        {"name": scope, "description": descriptions[scope]}
                        for scope in pending.scopes.split()
                    ],
                    "redirect_uri": pending.redirect_uri,
                    "loopback_redirect": urlsplit(pending.redirect_uri).hostname
                    in LOOPBACK_HOSTS,
                }
            ).data
        )


class DecisionView(OAuthLibMixin, APIView):
    """Records whether the user allows or denies the client, and returns where the
    browser goes next.

    Only the user bound by reading the handle can allow or deny the client:

        decision  password  row afterwards                         response
        --------  --------  -------------------------------------  ----------------
        deny      ignored   used                                   200, access_denied
        allow     correct   used                                   200, code
        allow     wrong     one more failure; used at the fifth    400
        any       any       (unbound, another user's, expired,     404
                            or already used)
    """

    permission_classes = [IsAuthenticated, SignedInInBrowser]

    @extend_schema(request=DecisionSerializer, responses=DecisionResultSerializer)
    def post(self, request, handle):
        decision = DecisionSerializer(data=request.data)
        decision.is_valid(raise_exception=True)
        allow = decision.validated_data["allow"]

        # The row is locked while the password is checked and the outcome recorded, so
        # two concurrent decisions cannot both use it. The 400 is raised after the
        # transaction commits, or raising it would roll back the failure count.
        with transaction.atomic():
            pending = (
                PendingAuthorization.objects.select_for_update()
                .filter(
                    id=handle,
                    user=request.user,
                    used=False,
                    expires_at__gt=timezone.now(),
                )
                .first()
            )
            if pending is None:
                raise NotFound
            password_ok = not allow or request.user.check_password(
                decision.validated_data["password"]
            )
            if password_ok:
                pending.used = True
            else:
                pending.failed_password_attempts += 1
                pending.used = pending.failed_password_attempts >= MAX_PASSWORD_ATTEMPTS
            pending.save(update_fields=["used", "failed_password_attempts"])

        if not password_ok:
            raise ValidationError({"password": "That password is incorrect."})

        try:
            # The view mixin's method, which takes the scopes as the stored string.
            uri, _, _, _ = self.create_authorization_response(
                request._request,
                scopes=pending.scopes,
                credentials=pending.credentials(),
                allow=allow,
            )
        except OAuthToolkitError as error:
            # Denying lands here too: django-oauth-toolkit raises `access_denied`
            # carrying the client's redirect URI and state.
            _, response = self.error_response(error)
            uri = response["url"]
        return Response(DecisionResultSerializer({"redirect_url": uri}).data)
