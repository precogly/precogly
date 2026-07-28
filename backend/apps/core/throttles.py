from rest_framework.throttling import AnonRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    """Limits login attempts per IP to prevent credential stuffing."""

    scope = "login"


class RegistrationRateThrottle(AnonRateThrottle):
    """Limits account creation per IP to prevent registration flooding."""

    scope = "registration"


class PasswordResetRateThrottle(AnonRateThrottle):
    """Limits password reset requests per IP to prevent email flooding."""

    scope = "password_reset"
