"""`/mcp` as gunicorn serves it: WSGI requests into `mount(Django)`.

`mcp/tests/test_http.py` covers the ASGI app on its own, with fakes. These build it
the way `config.wsgi` does, so the real token verifier, the real `request` and the
WSGI bridge all run, and they cover what only `mount` does: routing the two MCP
paths past Django, the 405 for GET and DELETE, and the 503 after a failed startup.

`TransactionTestCase`, because the endpoint runs on its own event loop thread, and
its database work happens on threads whose connections cannot see a `TestCase`
transaction.
"""

from __future__ import annotations

import io
import json
import secrets
from datetime import timedelta
from unittest import mock
from wsgiref.util import setup_testing_defaults

from asgiref.sync import SyncToAsync
from django.contrib.auth import get_user_model
from django.core.handlers.wsgi import WSGIHandler
from django.db import connections
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone
from oauth2_provider.models import get_access_token_model, set_token_value

from config.mcp_mount import mount

User = get_user_model()
AccessToken = get_access_token_model()

HOST = "precogly.example"
RESOURCE = f"https://{HOST}/mcp"
METADATA = "/.well-known/oauth-protected-resource/mcp"


def call(app, method, path, *, body=None, token=None):
    """Send one WSGI request to `app` and return its status code, headers and body."""
    payload = json.dumps(body).encode() if body is not None else b""
    environ = {}
    setup_testing_defaults(environ)
    environ.update(
        {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "HTTP_HOST": HOST,
            "SERVER_NAME": HOST,
            "SERVER_PORT": "443",
            "wsgi.url_scheme": "https",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": str(len(payload)),
            "HTTP_ACCEPT": "application/json, text/event-stream",
            "wsgi.input": io.BytesIO(payload),
        }
    )
    if token:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    started = {}

    def start_response(status, headers, exc_info=None):
        started["status"] = int(status.split()[0])
        started["headers"] = dict(headers)

    content = b"".join(app(environ, start_response))
    return started["status"], started["headers"], content.decode()


def execute(code):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "execute", "arguments": {"code": code}},
    }


@override_settings(MCP_RESOURCE_URL=RESOURCE, ALLOWED_HOSTS=[HOST])
class MountedEndpointTests(TransactionTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Once for the class: each `mount` starts an event loop thread and a sandbox
        # pool that live until the process exits, as they do in a gunicorn worker.
        # `staticmethod`, or `self.app` would bind the function and pass `self` first.
        cls.app = staticmethod(mount(WSGIHandler()))

    @classmethod
    def tearDownClass(cls):
        # The verifier and `request` call the database through `sync_to_async` from
        # the endpoint's loop thread. asgiref runs those calls on one shared executor
        # thread, which opens its own connection. Closed here, because an open
        # connection stops the test database being dropped at the end of the run.
        SyncToAsync.single_thread_executor.submit(connections.close_all).result()
        super().tearDownClass()

    def setUp(self):
        self.user = User.objects.create_user(
            username="ana@kestrel.test", email="ana@kestrel.test", password="pw"
        )
        self.token = secrets.token_urlsafe(30)
        access = AccessToken(
            user=self.user,
            scope="read",
            expires=timezone.now() + timedelta(hours=1),
            resource=[RESOURCE],
        )
        set_token_value(access, self.token)
        access.save()

    def test_a_read_runs_through_django_as_the_tokens_user(self):
        status, _, content = call(
            self.app,
            "POST",
            "/mcp",
            body=execute('(await request("GET", "/api/auth/user/"))["email"]'),
            token=self.token,
        )

        assert status == 200, content
        assert "ana@kestrel.test" in content

    def test_a_write_with_a_read_token_is_a_scope_challenge(self):
        status, headers, content = call(
            self.app,
            "POST",
            "/mcp",
            body=execute('await request("POST", "/api/zones/", body={})'),
            token=self.token,
        )

        assert status == 403, content
        assert 'scope="read write"' in headers["www-authenticate"]

    def test_the_metadata_document_is_served_from_the_origin_root(self):
        status, _, content = call(self.app, "GET", METADATA)

        assert status == 200, content
        assert json.loads(content)["resource"] == RESOURCE

    def test_a_stream_or_session_request_is_405(self):
        for method in ["GET", "DELETE"]:
            with self.subTest(method=method):
                status, _, _ = call(self.app, method, "/mcp", token=self.token)

                assert status == 405

    def test_every_other_path_reaches_django(self):
        # Django's answer to an unauthenticated API call, not the MCP app's 401.
        status, headers, _ = call(self.app, "GET", "/api/auth/user/")

        assert status == 401
        assert "resource_metadata" not in headers.get("WWW-Authenticate", "")


@override_settings(MCP_RESOURCE_URL=RESOURCE, ALLOWED_HOSTS=[HOST])
class FailedStartupTests(SimpleTestCase):
    def test_a_failed_startup_answers_503_on_the_mcp_paths_only(self):
        async def broken_schema():
            raise RuntimeError("schema generation failed")

        def django(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"django"]

        with (
            mock.patch("config.mcp_mount.schema", broken_schema),
            self.assertLogs("config.mcp_mount", "ERROR") as logged,
        ):
            app = mount(django)

        assert "schema generation failed" in logged.output[0]
        for path in ["/mcp", METADATA]:
            with self.subTest(path=path):
                status, _, content = call(app, "POST", path)

                assert status == 503
                assert "The MCP endpoint failed to start" in content
        assert call(app, "GET", "/api/zones/")[2] == "django"
