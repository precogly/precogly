from dj_rest_auth.registration.views import RegisterView
from dj_rest_auth.views import LoginView, PasswordResetView

from apps.core.throttles import (
    LoginRateThrottle,
    PasswordResetRateThrottle,
    RegistrationRateThrottle,
)


class ThrottledLoginView(LoginView):
    throttle_classes = [LoginRateThrottle]


class ThrottledRegisterView(RegisterView):
    throttle_classes = [RegistrationRateThrottle]


class ThrottledPasswordResetView(PasswordResetView):
    throttle_classes = [PasswordResetRateThrottle]
