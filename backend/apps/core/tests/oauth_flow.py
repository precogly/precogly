from urllib.parse import parse_qs, urlparse

from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken


def consent_for_code(test_client, user, password, params):
    """Walks `/o/authorize/` through the consent page's two API calls, as the React
    application makes them, and returns the authorization code.
    """
    consent_page = urlparse(
        test_client.get(reverse("oauth2_provider:authorize"), params)["Location"]
    )
    assert consent_page.path == "/oauth/consent"
    handle = parse_qs(consent_page.query)["id"][0]
    jwt = {"HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(user).access_token}"}

    read = test_client.get(reverse("pending-authorization", args=[handle]), **jwt)
    assert read.status_code == 200
    decision = test_client.post(
        reverse("pending-authorization-decision", args=[handle]),
        {"allow": True, "password": password},
        content_type="application/json",
        **jwt,
    )
    return parse_qs(urlparse(decision.json()["redirectUrl"]).query)["code"][0]
