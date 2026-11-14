"""
URL configuration for Precogly backend.
"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from oauth2_provider.urls import metadata_urlpatterns

# django-oauth-toolkit publishes two kinds of metadata: RFC 8414 for the authorization
# server, and RFC 9728 for a protected resource. Only the first describes this server.
# The second describes /mcp, and the MCP endpoint publishes its own at
# /.well-known/oauth-protected-resource/mcp, out of the same AuthSettings that its token
# verifier enforces — so the scopes it advertises are the scopes it requires. Routing
# both put two documents on that one path: Django builds its from
# OAUTH2_PROVIDER["SCOPES"], so it named /o as the authorization server and advertised
# `write` for an endpoint with no write tool, and the dispatch order in config/wsgi.py
# decided which one a client saw.
#
# Selected by name, since the resource patterns are the ones to leave out and the URL
# shapes belong to django-oauth-toolkit. A protected resource served by Django itself —
# /api/, say — would want them back, with /mcp excluded.
_authorization_server_metadata = [
    pattern
    for pattern in metadata_urlpatterns
    if pattern.name.startswith("oauth-server-metadata")
]

urlpatterns = [
    # Admin
    path("admin/", admin.site.urls),
    # Core API (health check, dashboard stats)
    path("api/", include("apps.core.urls")),
    # Authentication
    path("api/auth/", include("dj_rest_auth.urls")),
    path("api/auth/registration/", include("dj_rest_auth.registration.urls")),
    # A second, server-rendered login, because the React one yields a JWT and no
    # Django session and the authorize view needs a session. LOGIN_URL points here.
    #
    # The second sign-in is deliberate, not a gap to close: `mcp/docs/0007` keeps it
    # because consent granted by a session that has not just authenticated says nothing
    # about who granted it. `POST /api/auth/login/` already sets a `sessionid` —
    # dj_rest_auth's SESSION_LOGIN defaults to True — and the SPA discards it by sending
    # no `credentials: "include"`. Unifying would add a line, not remove one.
    #
    # TODO: the open question is the templates, not the logins. Five Django templates and
    #       a second CSS build target exist only to render this flow, and they go away
    #       only if consent moves into the SPA. `mcp/docs/0009` rejects that for now and
    #       its 2026-08-28 amendment says what the gate actually is: not the authorization
    #       code, which stays in django-oauth-toolkit behind one `OAuthLibMixin` call, but
    #       what would authenticate the consent POST. A DRF view authenticates with a JWT,
    #       and a JWT proves someone signed in up to an hour ago — which is the thing 0007
    #       refuses. Reopen when there is an answer to that: a short-lived re-auth token,
    #       or 0007's deferred bridge endpoint minting a fresh session.
    #
    #       Unowned, no issue filed.
    path("accounts/", include("allauth.urls")),
    # OAuth 2.1 authorization server, for MCP clients.
    path("o/", include("oauth2_provider.urls", namespace="oauth2_provider")),
    path("api/oauth/", include("apps.oauth.urls")),
    # RFC 8414 puts this document at the origin root rather than under the prefix
    # above, and strict clients look nowhere else.
    #
    # Both mounts describe the same "/o/" endpoints, because the views reverse their
    # endpoint URLs. They do not agree on `issuer`, which RFC 8414 makes the server's
    # identity: `oauth2_metadata_issuer` derives it from `request.path`, so each mount
    # names itself — "http://host" at the root and "http://host/o" under the prefix.
    #
    # Nothing routes a client to the prefixed copy today, so the two never meet:
    # discovery runs protected-resource document -> `authorization_servers` -> the root
    # document, which is self-consistent. It stops being latent the moment
    # COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS is set, because the `iss` parameter comes
    # from `oauth2_authorization_server_issuer`, which reverses
    # `oauth2_provider:oauth-server-metadata` and therefore resolves to the prefixed
    # mount. A client that read the root document then rejects its own authorization
    # response — RFC 9207 compares the two, and RFC 8414 comparison is exact string
    # comparison. Set OIDC_ISS_ENDPOINT alongside that flag and all three agree.
    path("", include((_authorization_server_metadata, "oauth2_provider_metadata"))),
    # App APIs
    path("api/", include("apps.threat_models.urls")),  # threat-models, reference-images
    path("api/", include("apps.diagrams.urls")),  # diagrams, dfd-templates
    path("api/", include("apps.systems.urls")),  # systems, components, data-flows
    path("api/", include("apps.compliance.urls")),  # frameworks, requirements
    path(
        "api/", include("apps.threats.urls")
    ),  # threat/countermeasure libraries, instances
    path("api/", include("apps.organizations.urls")),  # organizations, memberships
    path("api/", include("apps.packs.urls")),  # library packs, installations
    path("api/", include("apps.ai.urls")),  # per-tenant AI provider configs
    # API documentation
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
]

# Debug toolbar (development only)
if settings.DEBUG:
    # Checked as well as imported: the package stays importable with the app out
    # of INSTALLED_APPS, so an import guard on its own would mount `__debug__/`
    # with no middleware behind it.
    if getattr(settings, "DEBUG_TOOLBAR", False):
        try:
            import debug_toolbar

            urlpatterns = [
                path("__debug__/", include(debug_toolbar.urls)),
                *urlpatterns,
            ]
        except ImportError:
            pass

    # Serve media files in development
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
