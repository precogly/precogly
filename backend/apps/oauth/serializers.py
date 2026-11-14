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
