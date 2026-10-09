"""The project's DRF exception handler.

DRF turns its own exceptions into responses and leaves everything else as a
500. Service-layer errors that mean "this request is invalid" are mapped to
400 here, so a check that slipped past a serializer still answers as a bad
request rather than a server error (R11).
"""

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.views import set_rollback


def exception_handler(exc, context):
    from apps.threats.services import TargetError

    if isinstance(exc, TargetError):
        set_rollback()
        return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    return drf_exception_handler(exc, context)
