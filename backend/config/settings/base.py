"""
Base Django settings for Precogly backend.
"""

from datetime import timedelta
from pathlib import Path

import environ

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Initialize environ
env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, []),
)

# Read .env file if it exists
environ.Env.read_env(BASE_DIR / ".env")

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env("SECRET_KEY", default="django-insecure-change-me-in-production")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env("DEBUG")

ALLOWED_HOSTS = env("ALLOWED_HOSTS")


# Application definition

DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
]

THIRD_PARTY_APPS = [
    # REST Framework
    "rest_framework",
    "rest_framework.authtoken",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "django_filters",
    "corsheaders",
    "drf_spectacular",
    # Authentication
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "dj_rest_auth",
    "dj_rest_auth.registration",
    "oauth2_provider",
]

LOCAL_APPS = [
    "apps.core",
    "apps.ai",
    "apps.organizations",
    "apps.systems",
    "apps.threats",
    "apps.threat_models",
    "apps.diagrams",
    "apps.compliance",
    "apps.packs",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    "default": env.db(
        "DATABASE_URL",
        default="postgres://precogly:precogly_dev_password@localhost:5432/precogly",
    )
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
# The two server-rendered OAuth pages are the only thing here that needs static
# files; everything else a user sees is served by Vite. `css/auth.css` is built
# from the frontend's own tokens by `npm run build:auth-css` and committed,
# because this image has no Node in it.
STATICFILES_DIRS = [BASE_DIR / "static"]

MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"


# Library packs
#
# The directory holding the pack sources, containing `packs/`. It is one setting
# rather than a search of paths relative to BASE_DIR, because the container mounts
# it somewhere BASE_DIR cannot reach: a guess that misses leaves every library
# catalog empty, which reads as an empty database rather than as a missing mount.
LIBRARIES_PATH = Path(env("LIBRARIES_PATH", default=str(BASE_DIR.parent / "libraries")))


# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# Sites framework (required by allauth)
SITE_ID = 1


# Django REST Framework
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        # Order matters here. simplejwt's `get_validated_token`
        # raises InvalidToken on anything that is not one of its own JWTs, and DRF
        # does not catch it, so a class listed before this one ends the chain for
        # every OAuth access token. django-oauth-toolkit's returns None when the
        # token is not its own, so a JWT falls through it to simplejwt below.
        "oauth2_provider.contrib.rest_framework.OAuth2Authentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        # SessionAuthentication removed - it causes CSRF errors when stale sessionid
        # cookies are present during login. Since we use JWT, sessions aren't needed.
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_PAGINATION_CLASS": "apps.core.pagination.ClientSizedPagination",
    "EXCEPTION_HANDLER": "apps.core.exceptions.exception_handler",
    "PAGE_SIZE": 20,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    # Auto-convert snake_case <-> camelCase at API boundary
    "DEFAULT_RENDERER_CLASSES": (
        "djangorestframework_camel_case.render.CamelCaseJSONRenderer",
        "djangorestframework_camel_case.render.CamelCaseBrowsableAPIRenderer",
    ),
    "DEFAULT_PARSER_CLASSES": (
        "djangorestframework_camel_case.parser.CamelCaseJSONParser",
        "djangorestframework_camel_case.parser.CamelCaseFormParser",
        "djangorestframework_camel_case.parser.CamelCaseMultiPartParser",
    ),
}

# CamelCase parser settings - ignore auth fields used by dj-rest-auth
JSON_CAMEL_CASE = {
    "JSON_UNDERSCOREIZE": {
        "ignore_keys": (
            "password1",
            "password2",
            "new_password1",
            "new_password2",
            "email",
        ),
    },
}


# JWT Settings

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "AUTH_HEADER_TYPES": ("Bearer",),
}


# dj-rest-auth settings
REST_AUTH = {
    "USE_JWT": True,
    "JWT_AUTH_COOKIE": None,  # Don't use cookies, return tokens in response body
    "JWT_AUTH_REFRESH_COOKIE": None,
    "JWT_AUTH_HTTPONLY": False,
    "JWT_AUTH_RETURN_EXPIRATION": True,
    "OLD_PASSWORD_FIELD_ENABLED": True,
    # Use custom serializer that generates frontend URLs for password reset
    "PASSWORD_RESET_SERIALIZER": "apps.core.serializers.CustomPasswordResetSerializer",
}


# django-allauth settings
ACCOUNT_LOGIN_METHODS = {"email"}
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
ACCOUNT_EMAIL_VERIFICATION = "optional"

# Authentication backends
AUTHENTICATION_BACKENDS = [
    # Needed to login by username in Django admin
    "django.contrib.auth.backends.ModelBackend",
    # allauth specific authentication methods, such as login by email
    "allauth.account.auth_backends.AuthenticationBackend",
]

# Where django-oauth-toolkit's authorize view sends an unauthenticated user.
# Django's default is "/accounts/login/", which resolved to nothing here until
# allauth's URLs were routed in config.urls — the authorize endpoint answered a
# 404 rather than a login page.
LOGIN_URL = "/accounts/login/"


# OAuth 2.1 authorization server. Precogly issues the tokens; the MCP server is
# a resource server that validates them and holds no credential of its own.
OAUTH2_PROVIDER = {
    # These strings are the consent screen. A user deciding whether to connect
    # an agent reads them and nothing else, so they name what is at stake rather
    # than restating the verb.
    "SCOPES": {
        "read": "Read your threat models, diagrams and installed libraries",
        "write": "Create and change threat models on your behalf",
    },
    # The default is ["__all__"], which would hand every new client write access
    # without anyone choosing it. A client that wants to write has to ask.
    "DEFAULT_SCOPES": ["read"],
    # RFC 8252 exempts loopback redirects from port matching, because a native
    # client binds whatever ephemeral port is free. django-oauth-toolkit applies
    # the exemption to 127.0.0.1 and ::1 but withholds it from the hostname
    # "localhost", which §8.3 marks NOT RECOMMENDED. Clients spell it "localhost"
    # anyway, so without this the first authorization succeeds and every later
    # one fails on a redirect_uri mismatch that the request does not explain.
    "ALLOW_LOCALHOST_LOOPBACK": True,
    # Dynamic client registration (RFC 7591). Off by default, and the metadata
    # document gates `registration_endpoint` on this rather than on the URL
    # resolving — so with it off a client discovers a server it cannot register
    # with, and stops there.
    "DCR_ENABLED": True,
    # RFC 9700 (OAuth 2.0 Security Best Current Practice) hardening. Each of
    # these is enforced in `oauth2_validators`, not merely reflected in the
    # metadata document: without them this server advertises and accepts the
    # implicit and password grants and the "plain" PKCE challenge method, none
    # of which any client here has a reason to use.
    "COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT": True,
    "COMPLIANT_BCP_RFC9700_PASSWORD_GRANT": True,
    "COMPLIANT_BCP_RFC9700_PKCE_METHOD": True,
    # RFC 9700 §4.3.2 / RFC 6750 §5.3: an access token in the query string lands in
    # browser history, proxy logs and Referer headers. Nothing here sends one that
    # way — `/mcp` reads the header only, and the gate this sets
    # (`oauth2_backends.py:266`) fires solely on `access_token` in `request.GET` — so
    # this refuses a transport no client of ours uses.
    "COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT": True,
    # RFC 9207: name this server in the authorization response, so a client that
    # talks to several cannot be tricked into sending a code to the wrong one. Depends
    # on OIDC_ISS_ENDPOINT being pinned below — django-oauth-toolkit otherwise derives
    # `iss` from the prefixed metadata mount while the client read the root one, and
    # RFC 8414 compares issuers as exact strings, so a strict client rejects its own
    # authorization response.
    "COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS": True,
    # RFC 9700 §4.14.2 defines refresh token rotation as invalidating the presented
    # token *and* revoking the active one once a replay proves the token is held by
    # two parties: "the authorization server cannot determine which party submitted
    # the invalid refresh token, but it will revoke the active refresh token."
    # Rotation alone does the first half, so a stolen token outlives the client it
    # was stolen from — the thief keeps rotating while the victim silently
    # re-authorizes.
    #
    # The grace period is not optional alongside it. At 0 every replay is an attack,
    # including a client retrying after its connection dropped once the server had
    # already committed the rotation, and that costs a user their session over a lost
    # packet. 30s is Okta's default (Okta caps at 60, Ory Hydra at 300); it is
    # borrowed, not measured against how MCP clients actually retry.
    "REFRESH_TOKEN_REUSE_PROTECTION": True,
    "REFRESH_TOKEN_GRACE_PERIOD_SECONDS": 30,
    # Inactivity, not a deadline: `validate_refresh_token` puts the cutoff at the
    # access token's expiry plus this, and rotation mints a fresh access token, so a
    # client in daily use never expires and seven days of silence kills it. Left
    # unset, refresh tokens never expire at all, which RFC 10017 §6.3.2 forbids —
    # a maximum lifetime or an inactivity window, and django-oauth-toolkit can only
    # express the second. Seven days is Okta's inactivity window on the same sliding
    # mechanism.
    "REFRESH_TOKEN_EXPIRE_SECONDS": 60 * 60 * 24 * 7,
    # Registration has to be open, because a client registers itself before any
    # browser opens — there is no session to authenticate it with at that point.
    # The default, IsAuthenticatedDCRPermission, wants a session and so refuses
    # every MCP client. The cost is a public write endpoint on each deployment:
    # anyone who can reach it can create an Application row. That grants nothing
    # on its own — a registered client still has no token until a user logs in
    # and consents — but it is a surface, and it is worth rate-limiting before a
    # deployment is reachable from the internet.
    "DCR_REGISTRATION_PERMISSION_CLASSES": (
        "oauth2_provider.dcr.AllowAllDCRPermission",
    ),
}

# The MCP endpoint, served from this process by config.mcp_mount.
#
# MCP_RESOURCE_URL is an identity, not a routing hint: it is the audience a client
# names in its RFC 8707 `resource` parameter and the string the verifier requires to
# be on a token. It has to be the URL clients actually reach this deployment at, or
# every token is issued for one audience and checked against another.
MCP_RESOURCE_URL = env("MCP_RESOURCE_URL", default="http://localhost:8000/mcp")
MCP_ISSUER_URL = env("MCP_ISSUER_URL", default="http://localhost:8000")

# Pin the issuer instead of letting django-oauth-toolkit derive one per request.
# `config/urls.py` mounts the RFC 8414 document twice, and the derivation names
# whichever mount served it — so the root copy called this server
# "http://host" and the prefixed copy called it "http://host/o". RFC 8414 makes
# `issuer` the server's identity and compares it by exact string, so two names is
# one too many. Set here rather than in the block above because it has to agree
# with MCP_ISSUER_URL, which is what the MCP endpoint advertises, and one variable
# is what keeps them from drifting.
OAUTH2_PROVIDER["OIDC_ISS_ENDPOINT"] = MCP_ISSUER_URL

# Two RFC 9700 deployment findings this deployment answers with a reason rather than
# a setting. `manage.py check --deploy` is a merge gate (.github/workflows/ci.yml),
# so leaving them to be re-triaged on every run costs more than recording why.
#
# W008 — plaintext `http` redirect URIs. Removing "http" from
# ALLOWED_REDIRECT_URI_SCHEMES also disallows the RFC 8252 loopback callback, which
# is `http://127.0.0.1:<ephemeral>` for every native MCP client there is; the hint on
# the check says so itself. ALLOW_LOCALHOST_LOOPBACK above exists to support exactly
# that flow, so this is the scheme the product depends on, not one nobody removed.
#
# W006 — plaintext token storage. Wanted, and it breaks concurrent refresh. Measured
# 2026-08-28 against the dev stack: two simultaneous refreshes of the same token
# return one 200 and one 500, `AccessToken matching query does not exist`. The second
# request reaches the grace branch of `_save_bearer_token` (:1039-1058), which hands
# back `previous_access_token.token` — blank under hashed storage — and
# `authorization_flow_token_response` (views/base.py:505) then looks that empty string
# up with an unguarded `.get()`. django-oauth-toolkit's own E001 catches the same
# collision only when REFRESH_TOKEN_GRACE_PERIOD_SECONDS is non-zero; concurrency
# reaches the branch at any grace setting, so the check does not cover this. Revisit
# when that `.get()` is guarded upstream.
SILENCED_SYSTEM_CHECKS = [
    "oauth2_provider.W006",
    "oauth2_provider.W008",
]


# DRF Spectacular (OpenAPI/Swagger)
SPECTACULAR_SETTINGS = {
    "TITLE": "Precogly API",
    "DESCRIPTION": "Threat Modeling Platform API",
    "VERSION": "0.3.0",
    "SERVE_INCLUDE_SCHEMA": False,
}


# CORS Settings
CORS_ALLOWED_ORIGINS = env.list(
    "CORS_ALLOWED_ORIGINS",
    default=["http://localhost:5173", "http://127.0.0.1:5173"],
)
CORS_ALLOW_CREDENTIALS = True


# Email Settings
# Console backend for development - prints emails to terminal
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
DEFAULT_FROM_EMAIL = "noreply@precogly.dev"

# Frontend URL for password reset links
FRONTEND_URL = env("FRONTEND_URL", default="http://localhost:5173")


# AI threat suggestions
#
# Precogly talks to any OpenAI-compatible chat-completions endpoint, so a
# self-hoster can point this at a local model (LM Studio, Ollama, llama.cpp)
# or a hosted provider without changing code. The feature is OFF by default:
# nothing reaches out to a model until an operator opts in by flipping
# AI_SUGGESTIONS_ENABLED and pointing AI_BASE_URL at a running server.
#
# AI_BASE_URL is the OpenAI-style root that exposes /chat/completions; the
# LM Studio default (localhost:1234/v1) matches its out-of-the-box server.
# AI_API_KEY is optional because local servers usually don't require auth.
AI_SUGGESTIONS_ENABLED = env.bool("AI_SUGGESTIONS_ENABLED", default=False)
AI_BASE_URL = env("AI_BASE_URL", default="http://localhost:1234/v1")
AI_MODEL = env("AI_MODEL", default="local-model")
AI_API_KEY = env("AI_API_KEY", default="")
# Cap how long a suggestion request waits on the model before failing with an
# actionable error rather than hanging the user's request indefinitely.
AI_REQUEST_TIMEOUT = env.int("AI_REQUEST_TIMEOUT", default=60)

# Which addresses a model endpoint may resolve to, whether it came from
# AI_BASE_URL above or from an organization's own saved config. Organizations set
# their own base_url through the UI and Precogly fetches it server-side, which is
# what this guards; see apps.ai.url_policy.
#
#   allow-loopback   127.0.0.0/8 and ::1 as well as public addresses
#   deny-private     public addresses only
#
# Permissive here because running a model beside Precogly is what a local install
# is for — docker-compose.yml carries a socat sidecar so that http://localhost:1234
# reaches the host. production.py tightens it, which is where the deployment has
# already said it is exposed.
AI_PROVIDER_URL_POLICY = env.str("AI_PROVIDER_URL_POLICY", default="allow-loopback")

# The AI_* values above act as the *fallback* provider: a single operator-wide
# config used when an organization has not saved its own AIProviderConfig. Orgs
# that bring their own model override it per-tenant in the database.
#
# AI_SECRET_KEY encrypts those per-tenant API keys at rest (Fernet). It is kept
# separate from SECRET_KEY so the model-key encryption secret can be rotated or
# scoped independently of Django's signing key. It is only required once an
# operator stores a non-empty API key; local setups with no key (e.g. LM Studio)
# can leave it unset. Rotating it invalidates already-stored keys, which must
# then be re-entered.
AI_SECRET_KEY = env("AI_SECRET_KEY", default="")
