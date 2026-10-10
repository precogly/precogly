"""Step 1: Analyze an architecture image with a vision-capable model."""

from __future__ import annotations

import base64
import logging

from apps.ai.providers.base import AIProviderError
from apps.ai.resolver import resolve_provider
from apps.ai.utils import extract_json_object
from apps.systems.crossing import (
    ASSET_TYPES,
    AUTHENTICATION_TYPES,
    FLOW_TYPES,
    UNSPECIFIED,
    ZONE_TYPES,
    clean_type_list,
)

from .prompts import ANALYZE_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

# Keys we require in the analysis response.
_REQUIRED_KEYS = ("components", "flows", "zones", "systemScope", "questions")


def analyze_architecture_image(
    *,
    image_bytes: bytes,
    image_content_type: str,
    app_name: str,
    app_description: str,
    organization,
    user=None,
) -> dict:
    """Send an architecture image to a vision model and return structured analysis.

    Returns a dict with keys: components, flows, zones, systemScope,
    questions (``normalize_analysis``).  Raises ``AIProviderError`` if the model cannot be reached or
    returns unparseable output (e.g. the model does not support vision).
    """
    provider = resolve_provider(organization, feature="generate_dfd", user=user)

    image_b64 = base64.b64encode(image_bytes).decode("ascii")
    data_uri = f"data:{image_content_type};base64,{image_b64}"

    user_text = f"Application: {app_name}"
    if app_description:
        user_text += f"\nDescription: {app_description}"
    user_text += (
        "\n\nAnalyze the architecture diagram above and extract all components, "
        "flows, zones, and clarifying questions."
    )

    messages = [
        {"role": "system", "content": ANALYZE_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": [
                {
                    "type": "image_url",
                    "image_url": {"url": data_uri, "detail": "high"},
                },
                {"type": "text", "text": user_text},
            ],
        },
    ]

    completion = provider.complete(messages, temperature=0.3)
    result = extract_json_object(completion.content)

    if result is None:
        logger.error(
            "[analyze_image] Model response could not be parsed as JSON. "
            "Raw content (%d chars):\n%s",
            len(completion.content),
            completion.content[:2000],
        )
        raise AIProviderError(
            "The AI model returned a response that could not be parsed as JSON. "
            "The model may not support vision/image inputs. Try a vision-capable "
            "model such as GPT-4o."
        )

    return normalize_analysis(result, app_name, app_description)


def normalize_analysis(result: dict, app_name: str, app_description: str) -> dict:
    """The analysis in the shape the generate step and the dialog expect.

    Keys are ``components``, ``flows``, ``zones``, ``systemScope`` and
    ``questions`` (plan section 8). The old names (``dataFlows``,
    ``trustZones``, a component's ``trustZone``, a flow's ``authenticated``)
    are read too, since models repeat what they have seen. Types, kinds and
    authentication methods outside the allowed lists are dropped, never
    guessed.
    """
    for new_key, old_key in (("flows", "dataFlows"), ("zones", "trustZones")):
        if new_key not in result and old_key in result:
            result[new_key] = result.pop(old_key)
        result.pop(old_key, None)

    default_scope = {"name": app_name, "description": app_description}
    for key in _REQUIRED_KEYS:
        if key not in result:
            result[key] = default_scope if key == "systemScope" else []
        expected = dict if key == "systemScope" else list
        if not isinstance(result[key], expected):
            result[key] = default_scope if key == "systemScope" else []

    result["components"] = [
        _clean_component(component)
        for component in result["components"]
        if isinstance(component, dict)
    ]
    result["flows"] = [
        _clean_flow(flow) for flow in result["flows"] if isinstance(flow, dict)
    ]
    result["zones"] = [
        _clean_zone(zone) for zone in result["zones"] if isinstance(zone, dict)
    ]
    result["questions"] = [str(question) for question in result["questions"]]
    return result


def _clean_component(component: dict) -> dict:
    if "zone" not in component and "trustZone" in component:
        component["zone"] = component["trustZone"]
    component.pop("trustZone", None)
    if component.get("kind") not in ASSET_TYPES:
        component.pop("kind", None)
    return component


def _clean_flow(flow: dict) -> dict:
    if flow.get("type") not in FLOW_TYPES:
        flow.pop("type", None)
    flow["authentication"] = clean_authentication(flow)
    flow.pop("authenticated", None)
    return flow


def _clean_zone(zone: dict) -> dict:
    if zone.get("type") not in ZONE_TYPES:
        zone.pop("type", None)
    try:
        zone["trustLevel"] = max(0, min(100, int(zone.get("trustLevel"))))
    except (TypeError, ValueError):
        zone.pop("trustLevel", None)
    return zone


def clean_authentication(data: dict) -> list[str]:
    """A flow's authentication list from model output (I9).

    A valid ``authentication`` list is kept. Otherwise the old boolean maps
    the way DFD sync maps it: true is ``[unspecified]``, false is nothing.
    """
    raw = data.get("authentication")
    if isinstance(raw, list):
        try:
            return clean_type_list(
                [item for item in raw if item in AUTHENTICATION_TYPES],
                field="authentication",
            )
        except ValueError:
            return []
    return [UNSPECIFIED] if data.get("authenticated") is True else []
