"""Crossing requirements of a boundary (plan section 4.5, I5).

The spec's authentication and authorization lists include the value
``none``. "Required" means the list is not empty and does not contain
``none``; an empty list means not recorded; ``none`` cannot sit beside other
values. One helper answers the question and every reader uses it. The
frontend has the same helper.
"""

ZONE_TYPES = (
    "availability",
    "compliance",
    "data",
    "deployment",
    "functional",
    "geographic",
    "logical",
    "network",
    "organizational",
    "physical",
    "process",
    "tenant",
    "trust",
)
BOUNDARY_TYPES = (
    "data",
    "functional",
    "network",
    "organizational",
    "physical",
    "process",
    "trust",
)
FLOW_TYPES = (
    "control",
    "data",
    "energy",
    "event",
    "financial",
    "message",
    "physical",
    "process",
    "signal",
)
# Flow types whose threats come from the data-flow-minded packs; a library
# link with no ``flow_types`` applies to these only (section 4.6, H2).
DATA_LIKE_FLOW_TYPES = ("data", "message", "event")
ANY_FLOW_TYPE = "any"

ASSET_TYPES = (
    "actor",
    "agent",
    "api",
    "broker",
    "cache",
    "component",
    "container",
    "data",
    "data-store",
    "device",
    "endpoint",
    "function",
    "gateway",
    "infrastructure",
    "interface",
    "model",
    "module",
    "network",
    "process",
    "queue",
    "resource",
    "service",
    "stream",
    "subsystem",
    "system",
    "tool",
)
# The DFD role (category) picks the node shape; the kind is the spec asset
# type and defaults from the category when blank.
CATEGORY_TO_KIND = {
    "process": "process",
    "datastore": "data-store",
    "external_human_actor": "actor",
    "external_system_actor": "actor",
}
# Our own placeholder in an authentication list: authenticated, method not
# recorded (I9). The real method should be used wherever it is known.
UNSPECIFIED = "unspecified"

AUTHENTICATION_TYPES = (
    "api-key",
    "basic",
    "bearer",
    "biometric",
    "certificate",
    "digest",
    "eap",
    "fido2",
    "form",
    "hmac",
    "jwt",
    "kerberos",
    "ldap",
    "magic-link",
    "mtls",
    "none",
    "ntlm",
    "oauth1",
    "oauth2",
    "oidc",
    "pin",
    "psk",
    "push",
    "radius",
    "saml",
    "scram",
    "session-cookie",
    "ssh",
    "totp",
)
AUTHORIZATION_TYPES = (
    "abac",
    "acl",
    "capability",
    "dac",
    "mac",
    "none",
    "pbac",
    "radac",
    "rbac",
    "rebac",
)
NONE = "none"

# The nine spec keys of sessionManagement and their value types.
SESSION_MANAGEMENT_KEYS = {
    "accessTokenExpires": bool,
    "accessTokenTtl": int,
    "refreshToken": bool,
    "refreshTokenExpires": bool,
    "refreshTokenTtl": int,
    "idleTimeout": int,
    "absoluteTimeout": int,
    "userLogout": bool,
    "systemLogout": bool,
}
# The keys the boundary editor has a control for; sync owns these and
# leaves the two timeouts alone (M5, N1).
SESSION_EDITOR_KEYS = (
    "accessTokenExpires",
    "accessTokenTtl",
    "refreshToken",
    "refreshTokenExpires",
    "refreshTokenTtl",
    "userLogout",
    "systemLogout",
)
# Canvas edge keys (snake_case) -> session management keys.
CANVAS_SESSION_KEYS = {
    "access_token_expires": "accessTokenExpires",
    "access_token_ttl": "accessTokenTtl",
    "has_refresh_token": "refreshToken",
    "refresh_token_expires": "refreshTokenExpires",
    "refresh_token_ttl": "refreshTokenTtl",
    "can_user_logout": "userLogout",
    "can_system_logout": "systemLogout",
}


def requires(values) -> bool:
    """True when the list records a requirement: not empty and not ``none``."""
    if not values:
        return False
    return NONE not in values


def clean_type_list(values, *, field: str, allowed=None):
    """A validated list of spec values or custom names (strings).

    Raises ``ValueError`` with a message naming ``field`` when the value is not
    a list of non-empty strings, or when ``none`` sits beside other values.
    Any non-empty string is accepted on purpose: the spec's enum is too narrow
    to do without custom names (section 4.5), so ``allowed`` is informational
    and never enforced; duplicates are dropped.
    """
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError(f"{field} must be a list.")
    cleaned = []
    for value in values:
        name = value.get("name") if isinstance(value, dict) else value
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{field} entries must be non-empty strings.")
        name = name.strip()
        if name not in cleaned:
            cleaned.append(name)
    if NONE in cleaned and len(cleaned) > 1:
        raise ValueError(f"{field} cannot combine 'none' with other values.")
    return cleaned


def _snake(name: str) -> str:
    return "".join(f"_{c.lower()}" if c.isupper() else c for c in name)


# The API's camelCase parser snake_cases the keys inside the object on the
# way in; the stored keys are the spec's camelCase ones.
_SNAKE_TO_SPEC = {_snake(key): key for key in SESSION_MANAGEMENT_KEYS}


def clean_session_management(value) -> dict:
    """The validated ``session_management`` object: known keys, right types."""
    if value in (None, {}):
        return {}
    if not isinstance(value, dict):
        raise ValueError("session_management must be an object.")
    cleaned = {}
    for key, raw in value.items():
        key = _SNAKE_TO_SPEC.get(key, key)
        expected = SESSION_MANAGEMENT_KEYS.get(key)
        if expected is None:
            raise ValueError(f"session_management has no key '{key}'.")
        if raw is None:
            continue
        if expected is bool:
            if not isinstance(raw, bool):
                raise ValueError(f"session_management.{key} must be true or false.")
        elif isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise ValueError(
                f"session_management.{key} must be a whole number of seconds."
            )
        cleaned[key] = raw
    return cleaned


def session_management_from_canvas(existing: dict | None, edge_data: dict) -> dict:
    """Sync's view of session management: the editor's keys written from the
    canvas (missing means cleared), the two timeouts kept as they are."""
    result = {
        key: value
        for key, value in (existing or {}).items()
        if key not in SESSION_EDITOR_KEYS
    }
    for canvas_key, spec_key in CANVAS_SESSION_KEYS.items():
        raw = edge_data.get(canvas_key)
        if raw is None or raw == "":
            continue
        expected = SESSION_MANAGEMENT_KEYS[spec_key]
        if expected is bool:
            result[spec_key] = bool(raw)
        else:
            try:
                number = int(raw)
            except (TypeError, ValueError):
                continue
            if number >= 0:
                result[spec_key] = number
    return result


def kind_for_category(category: str | None) -> str:
    return CATEGORY_TO_KIND.get(category or "", "component")


def is_data_like(flow_type: str) -> bool:
    return flow_type in DATA_LIKE_FLOW_TYPES


def link_applies_to_flow_type(flow_types, flow_type: str) -> bool:
    """Whether a library link's ``flow_types`` admits a flow of ``flow_type``.

    Empty means the data-like types only; ``any`` means every type.
    """
    if not flow_types:
        return is_data_like(flow_type)
    if ANY_FLOW_TYPE in flow_types:
        return True
    return flow_type in flow_types
