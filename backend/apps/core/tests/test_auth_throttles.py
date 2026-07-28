"""Tests for authentication rate limiting.

Verifies that login, registration, and password reset endpoints enforce
per-IP request limits to prevent credential stuffing, registration
flooding, and password reset abuse.

Uses the production throttle rates from settings (login: 5/min,
registration: 3/min, password_reset: 3/min).
"""

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

User = get_user_model()


class LoginThrottleTests(TestCase):
    """Login endpoint must lock out after repeated failures (5/min)."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="throttle_test",
            email="throttle@test.org",
            password="correctpassword",
        )

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def _login(self, password="wrong"):
        return self.client.post(
            "/api/auth/login/",
            {"email": "throttle@test.org", "password": password},
            format="json",
        )

    def test_blocks_after_limit_exceeded(self):
        for _ in range(5):
            resp = self._login()
            self.assertIn(
                resp.status_code,
                (status.HTTP_400_BAD_REQUEST, status.HTTP_200_OK),
            )

        resp = self._login()
        self.assertEqual(resp.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_correct_password_also_blocked_after_limit(self):
        for _ in range(5):
            self._login()

        resp = self._login(password="correctpassword")
        self.assertEqual(resp.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_throttle_response_contains_retry_after(self):
        for _ in range(5):
            self._login()

        resp = self._login()
        self.assertEqual(resp.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn("Retry-After", resp.headers)


class RegistrationThrottleTests(TestCase):
    """Registration endpoint must limit account creation rate (3/min)."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def _register(self, n=0):
        return self.client.post(
            "/api/auth/registration/",
            {
                "email": f"newuser{n}@test.org",
                "username": f"newuser{n}",
                "password1": "strongpass123!",
                "password2": "strongpass123!",
            },
            format="json",
        )

    def test_blocks_after_limit_exceeded(self):
        for i in range(3):
            self._register(n=i)

        resp = self._register(n=99)
        self.assertEqual(resp.status_code, status.HTTP_429_TOO_MANY_REQUESTS)


class PasswordResetThrottleTests(TestCase):
    """Password reset endpoint must limit reset request rate (3/min)."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="resetuser",
            email="reset@test.org",
            password="testpass123",
        )

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def _reset(self):
        return self.client.post(
            "/api/auth/password/reset/",
            {"email": "reset@test.org"},
            format="json",
        )

    def test_blocks_after_limit_exceeded(self):
        for _ in range(3):
            self._reset()

        resp = self._reset()
        self.assertEqual(resp.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
