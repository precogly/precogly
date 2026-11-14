import secrets
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone
from oauth2_provider.models import get_application_model
from oauth2_provider.settings import oauth2_settings

# How long the user has to sign in and allow or deny the client. A shorter window
# fails a user who has to sign up or reset a password first. A longer one gives an
# attacker with a leaked handle more time to read it before the user does, which binds
# it to the attacker and leaves the user a 404. Ten minutes is arbitrary.
LIFETIME = timedelta(minutes=10)

# The keys oauthlib's `validate_authorization_request` returns for the authorization
# code grant with OpenID Connect off (oauthlib 3.3.1,
# `oauth2/rfc6749/grant_types/authorization_code.py`). `from_validated` raises on any
# other key, so an upgrade that adds one fails every authorization until the key gets a
# column or is dropped on purpose.
_REQUIRED = {"client_id", "redirect_uri", "response_type", "state", "request"}
_OPTIONAL = {"code_challenge", "code_challenge_method"}


def _new_handle():
    return secrets.token_urlsafe(32)


def _expiry():
    return timezone.now() + LIFETIME


class PendingAuthorization(models.Model):
    """An authorization request that django-oauth-toolkit has validated and the user has
    not yet allowed or denied.

    Each field of the request has its own column. A single JSON column holding the whole
    credentials dict would be simpler, but it would store whatever keys a future oauthlib
    returns and pass them to the grant unchecked.
    """

    # The handle in the consent page's URL. It reaches the browser, so it is 32 random
    # bytes rather than a sequential id; URL-safe base64 makes that 43 characters.
    id = models.CharField(
        primary_key=True, max_length=43, default=_new_handle, editable=False
    )
    application = models.ForeignKey(
        oauth2_settings.APPLICATION_MODEL, on_delete=models.CASCADE
    )
    # Null until the first user reads the handle. From then on, only that user can read
    # the request or post a decision on it.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE
    )

    redirect_uri = models.TextField()
    response_type = models.CharField(max_length=32)
    # An absent value is stored as "". oauthlib copies `state` to the grant only when it
    # is truthy, and django-oauth-toolkit saves a missing PKCE challenge as "", so
    # neither tells the two apart.
    state = models.TextField(blank=True, default="")
    code_challenge = models.CharField(max_length=128, blank=True, default="")
    code_challenge_method = models.CharField(max_length=10, blank=True, default="")
    # Space-separated, as django-oauth-toolkit stores a grant's scopes. Its view mixin's
    # `create_authorization_response` takes this string; `OAuthLibCore`'s takes a list.
    scopes = models.TextField()
    # RFC 8707 resource indicators. A list: django-oauth-toolkit refuses anything else
    # when it saves the grant.
    resource = models.JSONField(default=list, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=_expiry)
    used = models.BooleanField(default=False)

    def __str__(self):
        return f"Pending authorization for {self.application}"

    @classmethod
    def from_validated(cls, scopes, credentials, resource):
        """Builds an unsaved row from what `validate_authorization_request` returned.

        `scopes` is the list it returned. `resource` is the request's `resource` query
        parameters, which oauthlib does not validate and so does not return. Raises
        `ValueError` if `credentials` holds a key outside `_REQUIRED` and `_OPTIONAL`.
        """
        keys = set(credentials)
        missing = _REQUIRED - keys
        unknown = keys - _REQUIRED - _OPTIONAL
        if missing or unknown:
            raise ValueError(
                "The validated authorization request does not have the keys "
                "PendingAuthorization stores "
                f"(missing: {sorted(missing)}, unknown: {sorted(unknown)}). "
                "A django-oauth-toolkit or oauthlib upgrade has probably changed "
                "them; add a column for each new key, or drop it here on purpose."
            )

        # `request` is oauthlib's request object. It cannot be stored, and the decision
        # does not need it: django-oauth-toolkit's own `form_valid` builds the
        # credentials without it, and so does `credentials()`.
        return cls(
            application=get_application_model().objects.get(
                client_id=credentials["client_id"]
            ),
            redirect_uri=credentials["redirect_uri"],
            response_type=credentials["response_type"],
            state=credentials["state"] or "",
            code_challenge=credentials.get("code_challenge") or "",
            code_challenge_method=credentials.get("code_challenge_method") or "",
            scopes=" ".join(scopes),
            resource=list(resource),
        )

    def credentials(self):
        """Rebuilds the credentials dict that `create_authorization_response` takes.

        Matches the dict django-oauth-toolkit's `AuthorizationView.form_valid` builds:
        optional keys appear only when the request had them.
        """
        credentials = {
            "client_id": self.application.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": self.response_type,
            "state": self.state,
        }
        if self.code_challenge:
            credentials["code_challenge"] = self.code_challenge
            credentials["code_challenge_method"] = self.code_challenge_method
        if self.resource:
            credentials["resource"] = list(self.resource)
        return credentials
