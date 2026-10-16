"""Tests for the AI infrastructure.

The payoff of isolating this layer is that almost all of it is verifiable
without a database or a real model server. We mock ``requests`` to drive the
OpenAI-compatible adapter through every branch an operator might hit, check the
registry and crypto in isolation, and exercise the resolver's precedence rule.
Only the "org config overrides the settings fallback" case needs the database.
"""

from copy import deepcopy
from types import SimpleNamespace
from unittest import mock

import requests
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, TestCase, override_settings

from apps.ai import crypto, resolver
from apps.ai.providers import openai_compat
from apps.ai.providers.base import (
    AIDisabledError,
    AIProviderError,
    ResolvedConfig,
)
from apps.ai.providers.openai_compat import OpenAICompatProvider
from apps.ai.providers.registry import PROVIDER_TYPES, build_provider

CONFIG = ResolvedConfig(
    provider_type="openai_compat",
    base_url="http://localhost:1234/v1",
    model="local-model",
    api_key="",
    request_timeout=30,
)


def _response(*, status_code=200, json_body=None, text=""):
    """Stand-in for ``requests.Response`` with only what the adapter reads."""
    resp = mock.Mock(spec=["status_code", "json", "text"])
    resp.status_code = status_code
    resp.text = text
    if json_body is None:
        resp.json.side_effect = ValueError("no json")
    else:
        resp.json.return_value = json_body
    return resp


class OpenAICompatCompleteTests(SimpleTestCase):
    def setUp(self):
        self.provider = OpenAICompatProvider(CONFIG)

    def _ok_body(self, content="hello"):
        return {"choices": [{"message": {"content": content}}]}

    @mock.patch.object(openai_compat.requests, "post")
    def test_returns_assistant_content(self, post):
        post.return_value = _response(json_body=self._ok_body("the answer"))
        self.assertEqual(
            self.provider.complete([{"role": "user", "content": "hi"}]).content,
            "the answer",
        )

    @mock.patch.object(openai_compat.requests, "post")
    def test_usage_block_is_captured(self, post):
        body = self._ok_body("hi")
        body["usage"] = {
            "prompt_tokens": 10,
            "completion_tokens": 4,
            "total_tokens": 14,
        }
        post.return_value = _response(json_body=body)
        usage = self.provider.complete([{"role": "user", "content": "hi"}]).usage
        self.assertEqual(
            (usage.prompt_tokens, usage.completion_tokens, usage.total_tokens),
            (10, 4, 14),
        )

    @mock.patch.object(openai_compat.requests, "post")
    def test_missing_usage_block_yields_none(self, post):
        post.return_value = _response(json_body=self._ok_body("hi"))
        self.assertIsNone(
            self.provider.complete([{"role": "user", "content": "hi"}]).usage
        )

    @mock.patch.object(openai_compat.requests, "post")
    def test_total_defaults_to_sum_when_server_omits_it(self, post):
        body = self._ok_body("hi")
        body["usage"] = {"prompt_tokens": 10, "completion_tokens": 4}
        post.return_value = _response(json_body=body)
        self.assertEqual(
            self.provider.complete(
                [{"role": "user", "content": "hi"}]
            ).usage.total_tokens,
            14,
        )

    @mock.patch.object(openai_compat.requests, "post")
    def test_force_json_sets_response_format(self, post):
        post.return_value = _response(json_body=self._ok_body())
        self.provider.complete([{"role": "user", "content": "hi"}], force_json=True)
        self.assertEqual(
            post.call_args.kwargs["json"]["response_format"], {"type": "json_object"}
        )

    @mock.patch.object(openai_compat.requests, "post")
    def test_force_json_off_omits_response_format(self, post):
        post.return_value = _response(json_body=self._ok_body())
        self.provider.complete([{"role": "user", "content": "hi"}], force_json=False)
        self.assertNotIn("response_format", post.call_args.kwargs["json"])

    @mock.patch.object(openai_compat.requests, "post")
    def test_api_key_sets_bearer_header(self, post):
        post.return_value = _response(json_body=self._ok_body())
        provider = OpenAICompatProvider(
            ResolvedConfig(**{**CONFIG.__dict__, "api_key": "secret-token"})
        )
        provider.complete([{"role": "user", "content": "hi"}])
        self.assertEqual(
            post.call_args.kwargs["headers"]["Authorization"], "Bearer secret-token"
        )

    @mock.patch.object(openai_compat.requests, "post")
    def test_no_api_key_omits_auth_header(self, post):
        post.return_value = _response(json_body=self._ok_body())
        self.provider.complete([{"role": "user", "content": "hi"}])
        self.assertNotIn("Authorization", post.call_args.kwargs["headers"])

    @mock.patch.object(openai_compat.requests, "post")
    def test_connection_error_is_actionable(self, post):
        post.side_effect = requests.exceptions.ConnectionError()
        with self.assertRaises(AIProviderError) as ctx:
            self.provider.complete([{"role": "user", "content": "hi"}])
        self.assertIn("http://localhost:1234/v1", str(ctx.exception))

    @mock.patch.object(openai_compat.requests, "post")
    def test_timeout_is_actionable(self, post):
        post.side_effect = requests.exceptions.Timeout()
        with self.assertRaises(AIProviderError) as ctx:
            self.provider.complete([{"role": "user", "content": "hi"}])
        self.assertIn("did not respond", str(ctx.exception))

    @mock.patch.object(openai_compat.requests, "post")
    def test_non_200_surfaces_provider_detail(self, post):
        post.return_value = _response(
            status_code=401, json_body={"error": {"message": "invalid api key"}}
        )
        with self.assertRaises(AIProviderError) as ctx:
            self.provider.complete([{"role": "user", "content": "hi"}])
        self.assertIn("401", str(ctx.exception))
        self.assertIn("invalid api key", str(ctx.exception))

    @mock.patch.object(openai_compat.requests, "post")
    def test_unexpected_shape_raises_provider_error(self, post):
        post.return_value = _response(json_body={"unexpected": "shape"})
        with self.assertRaises(AIProviderError):
            self.provider.complete([{"role": "user", "content": "hi"}])

    @mock.patch.object(openai_compat.requests, "post")
    def test_retries_without_response_format_when_rejected(self, post):
        # Some servers (e.g. gpt-oss via LM Studio) reject json_object and only
        # accept json_schema/text; we drop the hint and retry once.
        rejected = _response(
            status_code=400,
            json_body={
                "error": {
                    "message": "'response_format.type' must be 'json_schema' or 'text'"
                }
            },
        )
        ok = _response(json_body=self._ok_body("recovered"))
        # The adapter reuses (and mutates) one payload dict across both calls, so
        # snapshot each call's body at send time rather than trusting mock's
        # by-reference history.
        responses = [rejected, ok]
        sent_payloads = []

        def record_and_respond(*args, **kwargs):
            sent_payloads.append(deepcopy(kwargs["json"]))
            return responses.pop(0)

        post.side_effect = record_and_respond
        result = self.provider.complete(
            [{"role": "user", "content": "hi"}], force_json=True
        )
        self.assertEqual(result.content, "recovered")
        self.assertEqual(post.call_count, 2)
        # First attempt offers the JSON hint; the retry drops it.
        self.assertIn("response_format", sent_payloads[0])
        self.assertNotIn("response_format", sent_payloads[1])

    @mock.patch.object(openai_compat.requests, "post")
    def test_unrelated_400_is_not_retried(self, post):
        post.return_value = _response(
            status_code=400, json_body={"error": {"message": "model not found"}}
        )
        with self.assertRaises(AIProviderError):
            self.provider.complete([{"role": "user", "content": "hi"}], force_json=True)
        self.assertEqual(post.call_count, 1)

    @mock.patch.object(openai_compat.requests, "post")
    def test_max_tokens_is_sent_in_payload(self, post):
        post.return_value = _response(json_body=self._ok_body())
        self.provider.complete([{"role": "user", "content": "hi"}])
        self.assertEqual(post.call_args.kwargs["json"]["max_tokens"], 4096)

    @mock.patch.object(openai_compat.requests, "post")
    def test_custom_max_tokens_is_sent(self, post):
        post.return_value = _response(json_body=self._ok_body())
        self.provider.complete([{"role": "user", "content": "hi"}], max_tokens=16384)
        self.assertEqual(post.call_args.kwargs["json"]["max_tokens"], 16384)

    @mock.patch.object(openai_compat.requests, "post")
    def test_retries_with_max_completion_tokens_when_max_tokens_rejected(self, post):
        rejected = _response(
            status_code=400,
            json_body={
                "error": {
                    "message": (
                        "Unsupported parameter: 'max_tokens' is not supported "
                        "with this model. Use 'max_completion_tokens' instead."
                    )
                }
            },
        )
        ok = _response(json_body=self._ok_body("recovered"))
        responses = [rejected, ok]
        sent_payloads = []

        def record_and_respond(*args, **kwargs):
            sent_payloads.append(deepcopy(kwargs["json"]))
            return responses.pop(0)

        post.side_effect = record_and_respond
        result = self.provider.complete([{"role": "user", "content": "hi"}])
        self.assertEqual(result.content, "recovered")
        self.assertEqual(post.call_count, 2)
        # First attempt uses max_tokens; the retry swaps to max_completion_tokens.
        self.assertIn("max_tokens", sent_payloads[0])
        self.assertNotIn("max_completion_tokens", sent_payloads[0])
        self.assertNotIn("max_tokens", sent_payloads[1])
        self.assertEqual(sent_payloads[1]["max_completion_tokens"], 4096)


class OpenAICompatTestConnectionTests(SimpleTestCase):
    def setUp(self):
        self.provider = OpenAICompatProvider(CONFIG)

    @mock.patch.object(openai_compat.requests, "get")
    def test_reachable_reports_model_count(self, get):
        get.return_value = _response(json_body={"data": [{"id": "a"}, {"id": "b"}]})
        health = self.provider.test_connection()
        self.assertTrue(health.ok)
        self.assertIn("2 model", health.detail)

    @mock.patch.object(openai_compat.requests, "get")
    def test_connection_refused_is_reported_not_raised(self, get):
        get.side_effect = requests.exceptions.ConnectionError()
        health = self.provider.test_connection()
        self.assertFalse(health.ok)
        self.assertIn("localhost:1234", health.detail)

    @mock.patch.object(openai_compat.requests, "get")
    def test_non_200_is_reported_not_raised(self, get):
        get.return_value = _response(
            status_code=403, json_body={"error": {"message": "forbidden"}}
        )
        health = self.provider.test_connection()
        self.assertFalse(health.ok)
        self.assertIn("403", health.detail)


class RegistryTests(SimpleTestCase):
    def test_builds_known_provider(self):
        provider = build_provider(CONFIG)
        self.assertIsInstance(provider, OpenAICompatProvider)

    def test_unknown_type_raises_named_error(self):
        bad = ResolvedConfig(**{**CONFIG.__dict__, "provider_type": "bedrock"})
        with self.assertRaises(AIProviderError) as ctx:
            build_provider(bad)
        self.assertIn("bedrock", str(ctx.exception))

    def test_openai_compat_is_registered(self):
        self.assertIn("openai_compat", PROVIDER_TYPES)


@override_settings(AI_SECRET_KEY="unit-test-secret")
class CryptoTests(SimpleTestCase):
    def test_round_trip(self):
        token = crypto.encrypt("sk-live-123")
        self.assertEqual(crypto.decrypt(token), "sk-live-123")

    def test_ciphertext_is_not_plaintext(self):
        token = crypto.encrypt("sk-live-123")
        self.assertNotIn("sk-live-123", token)

    def test_empty_stays_empty(self):
        self.assertEqual(crypto.encrypt(""), "")
        self.assertEqual(crypto.decrypt(""), "")

    def test_wrong_secret_raises_actionable_error(self):
        token = crypto.encrypt("sk-live-123")
        with (
            override_settings(AI_SECRET_KEY="a-different-secret"),
            self.assertRaises(AIProviderError),
        ):
            crypto.decrypt(token)


class CryptoMisconfigurationTests(SimpleTestCase):
    @override_settings(AI_SECRET_KEY="")
    def test_encrypting_without_secret_is_named(self):
        with self.assertRaises(ImproperlyConfigured):
            crypto.encrypt("sk-live-123")


class ResolverFallbackTests(SimpleTestCase):
    """Org-independent precedence: settings fallback and the disabled path."""

    SETTINGS_FALLBACK = {
        "AI_SUGGESTIONS_ENABLED": True,
        "AI_BASE_URL": "http://settings-default:1234/v1",
        "AI_MODEL": "settings-model",
        "AI_API_KEY": "",
        "AI_REQUEST_TIMEOUT": 42,
    }

    @override_settings(**SETTINGS_FALLBACK)
    def test_settings_default_used_when_no_org(self):
        config = resolver.resolve_config(None)
        self.assertEqual(config.base_url, "http://settings-default:1234/v1")
        self.assertEqual(config.request_timeout, 42)

    @override_settings(AI_SUGGESTIONS_ENABLED=False)
    def test_disabled_when_nothing_configured(self):
        self.assertIsNone(resolver.settings_default_config())
        with self.assertRaises(AIDisabledError):
            resolver.resolve_config(None)

    def test_organization_for_component_reads_the_blueprints_model(self):
        org = SimpleNamespace(name="via-blueprint")
        component = SimpleNamespace(
            blueprint_id=7,
            blueprint=SimpleNamespace(threat_model=SimpleNamespace(organization=org)),
            # The inventory link is not a tenancy path any more.
            orgsystem=SimpleNamespace(organization=SimpleNamespace(name="other")),
        )
        self.assertIs(resolver.organization_for_component(component), org)

    def test_organization_for_component_none_when_unlinked(self):
        component = SimpleNamespace(blueprint_id=None, blueprint=None, orgsystem=None)
        self.assertIsNone(resolver.organization_for_component(component))


class ResolverOrgConfigTests(TestCase):
    """The one path that needs the DB: a saved org config overrides the fallback."""

    @classmethod
    def setUpTestData(cls):
        from apps.ai.models import AIProviderConfig
        from apps.organizations.models import Organization

        cls.org = Organization.objects.create(name="Acme")
        cls.config = AIProviderConfig.objects.create(
            organization=cls.org,
            name="Acme local model",
            base_url="http://org-model:9999/v1",
            model="org-model",
            is_default=True,
            enabled=True,
        )

    @override_settings(
        AI_SUGGESTIONS_ENABLED=True,
        AI_BASE_URL="http://settings-default:1234/v1",
        AI_MODEL="settings-model",
        AI_API_KEY="",
        AI_REQUEST_TIMEOUT=60,
    )
    def test_org_default_overrides_settings_fallback(self):
        config = resolver.resolve_config(self.org)
        self.assertEqual(config.base_url, "http://org-model:9999/v1")
        self.assertEqual(config.model, "org-model")

    @override_settings(
        AI_SUGGESTIONS_ENABLED=True,
        AI_BASE_URL="http://settings-default:1234/v1",
        AI_MODEL="settings-model",
        AI_API_KEY="",
        AI_REQUEST_TIMEOUT=60,
    )
    def test_disabled_org_config_falls_back_to_settings(self):
        self.config.enabled = False
        self.config.save(update_fields=["enabled"])
        config = resolver.resolve_config(self.org)
        self.assertEqual(config.base_url, "http://settings-default:1234/v1")

    @override_settings(AI_SECRET_KEY="unit-test-secret")
    def test_api_key_persists_encrypted_and_round_trips(self):
        self.config.set_api_key("sk-org-secret")
        self.config.save(update_fields=["api_key_encrypted"])
        self.assertNotIn("sk-org-secret", self.config.api_key_encrypted)
        self.assertEqual(self.config.api_key, "sk-org-secret")
