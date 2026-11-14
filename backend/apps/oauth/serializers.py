from rest_framework import serializers


class ScopeSerializer(serializers.Serializer):
    name = serializers.CharField()
    description = serializers.CharField()


class PendingAuthorizationSerializer(serializers.Serializer):
    """What the consent page shows before the user allows or denies a client.

    The registering client supplies `client_name` during dynamic client registration,
    unvetted, so the page must render it as plain text, never as HTML.
    """

    client_name = serializers.CharField()
    scopes = ScopeSerializer(many=True)
    redirect_uri = serializers.CharField()
    # True when the redirect goes to this machine. Any local program can register
    # such a client, so the page warns before the user approves it.
    loopback_redirect = serializers.BooleanField()


class DecisionSerializer(serializers.Serializer):
    allow = serializers.BooleanField()
    # Required to allow, not to deny: approving grants access to the account, refusing
    # grants nothing.
    password = serializers.CharField(
        required=False, write_only=True, trim_whitespace=False
    )

    def validate(self, attrs):
        if attrs["allow"] and not attrs.get("password"):
            raise serializers.ValidationError(
                {"password": "Enter your password to allow access."}
            )
        return attrs


class DecisionResultSerializer(serializers.Serializer):
    # Where the consent page sends the browser: the client's redirect URI with a code,
    # or with `error=access_denied`.
    redirect_url = serializers.CharField()
