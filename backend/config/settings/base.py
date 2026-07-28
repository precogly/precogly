"""
Base Django settings for Precogly backend.
"""

import environ
from pathlib import Path

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

MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"


# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# Sites framework (required by allauth)
SITE_ID = 1


# Django REST Framework
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
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
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
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
    "DEFAULT_THROTTLE_RATES": {
        "login": "5/min",
        "registration": "3/min",
        "password_reset": "3/min",
    },
}

# CamelCase parser settings - ignore auth fields used by dj-rest-auth
JSON_CAMEL_CASE = {
    "JSON_UNDERSCOREIZE": {
        "ignore_keys": ("password1", "password2", "new_password1", "new_password2", "email"),
    },
}


# JWT Settings
from datetime import timedelta

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


# DRF Spectacular (OpenAPI/Swagger)
SPECTACULAR_SETTINGS = {
    "TITLE": "Precogly API",
    "DESCRIPTION": "Threat Modeling Platform API",
    "VERSION": "0.2.0",
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
