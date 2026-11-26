from urllib.parse import urlencode, urlsplit

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.utils import timezone
from django.views.generic import View
from drf_spectacular.utils import extend_schema
from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_refresh_token_model,
)
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
    AuthorizedApplicationSerializer,
    DecisionResultSerializer,
    DecisionSerializer,
    PendingAuthorizationSerializer,
)

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class AuthorizeView(OAuthLibMixin, View):
    """Stores a validated authorization request and sends the browser to the consent page.

    django-oauth-toolkit's `AuthorizationView` requires a Django session at this point;
    this view requires none, because the user signs in on the consent page instead.
    It drops the toolkit's `skip_authorization`, `approval_prompt=auto` and
    `prompt=login`, which all need a signed-in user here. Dynamic registration never
    sets `skip_authorization`, and `REQUEST_APPROVAL_PROMPT` is left at `force`.
    """

    def get(self, request, *args, **kwargs):
        try:
            scopes, credentials = self.validate_authorization_request(request)
        except OAuthToolkitError as error:
            return self.error_response(error, allowed_schemes=None)

        application = get_application_model().objects.get(
            client_id=credentials["client_id"]
        )
        # Every token must name the MCP endpoint, and nothing else, as its resource.
        # django-oauth-toolkit checks a token's audience only when it has one, and by
        # URL prefix, so a token with no resource, or with the origin among its
        # resources, works on every `/api/` endpoint, where `read` and `write` are not
        # checked. Compared exactly, as the MCP token verifier compares it.
        resource = request.GET.getlist("resource")
        if set(resource) != {settings.MCP_RESOURCE_URL}:
            error = OAuthToolkitError(
                error=CustomOAuth2Error(
                    error="invalid_target",
                    description=(
                        f"Tokens here are issued only for the MCP endpoint: send "
                        f"resource={settings.MCP_RESOURCE_URL} and no other resource."
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
        return HttpResponseRedirect(error_page_url(response["error"]))


def error_page_url(oauthlib_error):
    """Return the URL of the SPA's error page for an error that cannot go back to the
    client.

    Used when there is no trusted redirect URI: an unknown client, or a redirect URI it
    never registered. `error_description` comes from the query string, which a crafted
    link controls, so the SPA must render it as plain text, never as HTML.
    """
    query = urlencode(
        {
            "error": oauthlib_error.error,
            "error_description": oauthlib_error.description or "",
        }
    )
    return f"{settings.FRONTEND_URL}/oauth/error?{query}"


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

        # The user approved this client, so revoke its earlier tokens and grants:
        # the code issued below becomes its only access. Must stay above
        # `create_authorization_response`, or it deletes the grant issued there.
        if allow:
            revoke_access(request.user, pending.application_id)

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
            # carrying the client's redirect URI and state. With no trusted redirect
            # URI, `url` is a bare `?error=…` that would send the browser back to the
            # consent page, so the SPA's error page shows it instead.
            redirect, response = self.error_response(error)
            uri = response["url"] if redirect else error_page_url(response["error"])
        return Response(DecisionResultSerializer({"redirect_url": uri}).data)


def live_access_tokens(user):
    """The user's access tokens that still grant access, now or after a refresh.

    A client is authorized while it holds one of these: an unexpired access token, or
    an expired one whose refresh token has not been revoked.
    """
    return (
        get_access_token_model()
        .objects.filter(user=user)
        .filter(
            Q(expires__gt=timezone.now())
            # `refresh_token__isnull=False` keeps out tokens issued without a refresh
            # token, whose missing join would otherwise read as "not revoked".
            | Q(refresh_token__isnull=False, refresh_token__revoked__isnull=True)
        )
    )


def revoke_access(user, application_id):
    """Revoke every token and grant `user` holds for an application."""
    # Refresh tokens first: `revoke` marks each one revoked and deletes the access
    # token it last issued. Deleting the remaining access tokens and grants then
    # leaves the client nothing to use or exchange.
    with transaction.atomic():
        for refresh_token in get_refresh_token_model().objects.filter(
            user=user, application_id=application_id, revoked__isnull=True
        ):
            refresh_token.revoke()
        get_access_token_model().objects.filter(
            user=user, application_id=application_id
        ).delete()
        get_grant_model().objects.filter(
            user=user, application_id=application_id
        ).delete()


class AuthorizedApplicationsView(APIView):
    """Lists the MCP clients that can currently act on the user's account."""

    permission_classes = [IsAuthenticated, SignedInInBrowser]

    @extend_schema(responses=AuthorizedApplicationSerializer(many=True))
    def get(self, request):
        descriptions = get_scopes_backend().get_all_scopes()
        by_application = {}
        for token in live_access_tokens(request.user).select_related("application"):
            application = token.application
            if application.pk not in by_application:
                # `redirect_uris` is space-separated. As of 2026-11-14, Claude Code and
                # opencode each register a single URI, so the host of the first entry
                # is where the client runs.
                redirect_host = (
                    urlsplit(application.redirect_uris.split()[0]).hostname
                    if application.redirect_uris
                    else ""
                ) or ""
                by_application[application.pk] = {
                    "id": application.pk,
                    "name": application.name,
                    "scopes": set(),
                    "registered_at": application.created,
                    "runs_locally": redirect_host in LOOPBACK_HOSTS,
                    "redirect_host": redirect_host,
                }
            by_application[application.pk]["scopes"].update(token.scope.split())

        applications = sorted(
            by_application.values(),
            key=lambda entry: entry["registered_at"],
            reverse=True,
        )
        for entry in applications:
            entry["scopes"] = [
                {"name": scope, "description": descriptions.get(scope, scope)}
                for scope in sorted(entry["scopes"])
            ]
        return Response(AuthorizedApplicationSerializer(applications, many=True).data)


class AuthorizedApplicationView(APIView):
    """Revokes one MCP client's access to the user's account."""

    permission_classes = [IsAuthenticated, SignedInInBrowser]

    @extend_schema(responses={204: None})
    def delete(self, request, application_id):
        if (
            not live_access_tokens(request.user)
            .filter(application_id=application_id)
            .exists()
        ):
            raise NotFound

        revoke_access(request.user, application_id)
        return Response(status=204)
