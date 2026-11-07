"""`request` refuses writes unless the token carries the `write` scope.

No database: `_dispatch_as` is replaced with a recorder, so these see only whether
the check let a call through.
"""

from unittest import mock

import pytest
from asgiref.sync import async_to_sync
from django.test import SimpleTestCase
from mcp.server.auth.provider import AccessToken

from apps.core.mcp import api
from apps.core.mcp.errors import APIError


def token(*scopes):
    return AccessToken(token="t", client_id="c", scopes=list(scopes), subject="42")


class WriteScopeTests(SimpleTestCase):
    def setUp(self):
        patcher = mock.patch.object(api, "_dispatch_as", return_value=(200, None))
        self.dispatched = patcher.start()
        self.addCleanup(patcher.stop)

    def call(self, access_token, method, path="/api/zones/"):
        return async_to_sync(api.request)(access_token, method, path)

    def test_a_read_only_token_cannot_write(self):
        for method in ["POST", "PUT", "PATCH", "DELETE", "post"]:
            with self.subTest(method=method), pytest.raises(APIError, match="write"):
                self.call(token("read"), method)
        self.dispatched.assert_not_called()

    def test_a_write_token_is_dispatched_as_its_user(self):
        self.call(token("read", "write"), "post")

        self.dispatched.assert_called_once_with(42, "POST", "/api/zones/")

    def test_reads_need_no_write_scope(self):
        for method in ["GET", "HEAD", "OPTIONS", "get"]:
            with self.subTest(method=method):
                self.call(token("read"), method)
        assert self.dispatched.call_count == 4
