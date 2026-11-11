"""Serializer for per-tenant AI provider configuration.

The one subtlety here is the API key. It is *write-only*: the client may send a
new value, but the stored key is never serialized back — a database read should
not be a way to recover a customer's provider credential. So instead of exposing
the ciphertext (or, worse, the plaintext), the serializer offers two things:

* a write-only ``api_key`` field that, when non-blank, replaces the stored key;
* a read-only ``has_api_key`` flag so the UI can show "a key is set" and offer a
  "replace" affordance without ever seeing the secret.

This mirrors the admin form's posture (:mod:`apps.ai.admin`) and is the same
contract the settings UI consumes.
"""

from rest_framework import serializers
from rest_framework.validators import UniqueTogetherValidator

from .models import AIProviderConfig
from .url_policy import URLPolicyError, check_url


class AIProviderConfigSerializer(serializers.ModelSerializer):
    """Read/write a config without ever exposing the stored API key."""

    # Accepted on write, never rendered. Blank (or omitted) means "leave the
    # stored key untouched"; a value replaces it. The actual encryption happens
    # in the viewset via AIProviderConfig.set_api_key.
    api_key = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        style={"input_type": "password"},
        help_text="Leave blank to keep the existing key; send a value to replace it.",
    )
    # Lets the UI distinguish "no key" from "key set" without leaking the secret.
    has_api_key = serializers.SerializerMethodField()

    class Meta:
        model = AIProviderConfig
        fields = [
            "id",
            "organization",
            "name",
            "provider_type",
            "base_url",
            "model",
            "request_timeout",
            "is_default",
            "enabled",
            "api_key",
            "has_api_key",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "has_api_key", "created_at", "updated_at"]

    def get_validators(self):
        """Drop the validator DRF derives from the one-default-per-org constraint.

        Since DRF 3.18 a conditional UniqueConstraint becomes a serializer
        validator, which would reject promoting a new default while the old one
        still exists. The viewset demotes the old default in the same transaction
        as the save, and the DB constraint still backs that up.
        """
        return [
            validator
            for validator in super().get_validators()
            if not (
                isinstance(validator, UniqueTogetherValidator)
                and getattr(validator, "condition", None) is not None
            )
        ]

    def get_has_api_key(self, obj: AIProviderConfig) -> bool:
        return bool(obj.api_key_encrypted)

    def validate_base_url(self, value: str) -> str:
        """Reject an endpoint this deployment will refuse to fetch anyway.

        This is the error message, not the control. A name resolves again at
        request time and can answer differently by then, so the provider
        re-checks before every call; what this adds is a 400 against the field
        while the operator is still looking at the form, instead of a config
        that saves cleanly and fails later.
        """
        try:
            check_url(value)
        except URLPolicyError as err:
            raise serializers.ValidationError(str(err)) from err
        return value
