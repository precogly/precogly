"""MCP server exposing Precogly threat modeling to language model agents.

Tools are added in the order recorded in docs/0002-tool-implementation-order.md:
`list_threat_models`, then the three catalog searches.

The searches fetch a whole catalog and filter it here rather than passing the query
to the viewset. The catalogs are unpaginated, which is what makes that affordable
(docs/0005-code-execution-over-tools.md), and filtering here reaches fields
`search_fields` does not — a threat's taxonomy mappings are on every row and no
server-side search matches them.

Two transports, and the difference between them is how a tool reaches Precogly. No
tool fetches for itself; each reads through a `PrecoglyData` its caller supplied
(docs/0008). Mounted inside Precogly (`asgi_app`), that reader goes to the ORM as the
user whose token the verifier resolved. Over stdio (`main`), there is no request and
no browser, so it goes to the REST API with a token from the environment — which is
what the MCP specification directs a stdio server to do.

Nothing here validates a token or reads a database. Both the verifier and the reader
arrive from the caller, so this package never imports Django and Precogly stays the
only thing that knows how its own tokens are stored or where its rows live.
"""

from __future__ import annotations

import functools
import os
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from importlib.metadata import version
from typing import Any, Literal

import httpx2
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.context import Context
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from starlette.applications import Starlette

# Absolute rather than relative, so this module loads both as `python -m
# precogly_mcp.server` and by file path. `mcp dev` reads the file with
# `spec_from_file_location`, which gives it no parent package, and a relative import
# there fails with "attempted relative import with no known parent package".
from precogly_mcp.access import HTTPReader, PrecoglyReader, ReaderFor
from precogly_mcp.client import PrecoglyAPIError
from precogly_mcp.models import (
    LibraryComponent,
    LibraryComponentMatches,
    LibraryCountermeasure,
    LibraryCountermeasureMatches,
    LibraryThreat,
    LibraryThreatMatches,
    ThreatModelListing,
    ThreatModelSummary,
)

# Empty is treated as unset. An MCP client interpolating a variable into the server's
# environment — opencode's `{env:PRECOGLY_URL}` — can hand over an empty string when the
# variable is not set, and that reaches the caller as "Could not reach Precogly at :",
# which names the wrong problem.
_BASE_URL = os.environ.get("PRECOGLY_URL") or "http://localhost:8000"


def http_client() -> httpx2.AsyncClient:
    """Build the HTTP client a tool call uses.

    A module-level function rather than a parameter because a tool's parameters are its
    public schema — adding one for a transport would advertise it to every caller. Tests
    replace this to supply a `MockTransport`.
    """
    return httpx2.AsyncClient(timeout=10)


def _surface_api_errors(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Return PrecoglyAPIError as a tool-level error instead of letting it propagate.

    mcp >=2.1 wraps unhandled tool exceptions in a generic message. These errors
    are written for the calling agent and must survive the boundary.
    """

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await fn(*args, **kwargs)
        except PrecoglyAPIError as exc:
            return CallToolResult(
                content=[TextContent(type="text", text=str(exc))],
                is_error=True,
            )

    return wrapper


def _read(ctx: Context[ReaderFor, Any]) -> PrecoglyReader:
    """The reader for whoever made this call.

    The mounting application decides what that is. It is handed the access token the
    verifier resolved, so a tool mounted in Precogly reaches exactly what the user who
    authorized it can reach, and nothing else needs to know how.
    """
    reader_for = ctx.request_context.lifespan_context
    return reader_for(get_access_token())


# Tools are plain functions, registered in `build_server` rather than by decorator.
# The server object cannot exist at import time any more: `AuthSettings` and the
# token verifier are constructor arguments, and both differ between the mounted and
# stdio transports.

# Annotations are how a client decides whether a call needs a human. Absent them, a
# cautious client has to assume the worst about what is only ever a read.
_LIST_ANNOTATIONS = ToolAnnotations(
    # Only ever issues a GET.
    read_only_hint=True,
    # Calling it twice changes nothing, so a client is free to retry.
    idempotent_hint=True,
    # Closed world: it queries one known deployment for that deployment's own
    # records. Not a search over anything unbounded.
    open_world_hint=False,
)


@_surface_api_errors
async def list_threat_models(
    ctx: Context[ReaderFor, Any],
    organization_id: int | None = None,
) -> ThreatModelListing:
    """List threat models in the caller's organizations, most recently updated first.

    Each entry carries what a choice between models turns on: name, description,
    criticality, owner, owning team, when it last changed, and the compliance frameworks
    it touches. It does not carry a model's contents.

    `frameworks` is incidence, not coverage. A framework is listed when at least one
    countermeasure maps to at least one of its requirements, so a model addressing a
    single control appears identically to one addressing every control. It answers
    "which models touch SOC 2 at all", not "which models are SOC 2 compliant".

    `total` is how many you can see, which is not always how many are returned. Read
    it before answering "how many" or "list them all".
    """
    listing = await _read(ctx).threat_models(organization_id)
    return ThreatModelListing(
        models=[ThreatModelSummary.model_validate(row) for row in listing.rows],
        total=listing.total,
    )


# The three catalog searches share a matcher. Everything else about them differs — the
# catalog, the projection, and which fields a query is matched against — which is why
# they are three tools and not one with a `kind` argument.


def _matches(query: str, *fields: str) -> bool:
    """Case-insensitive substring match against any of `fields`.

    `casefold` rather than `lower`, since the catalogs carry pack-supplied prose and
    nothing guarantees it is ASCII.
    """
    needle = query.casefold()
    return any(needle in field.casefold() for field in fields)


# Shared by all three, so a client reading the tool list sees the same promises on each.
_CATALOG_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    idempotent_hint=True,
    # The catalog is one deployment's own records, and every row of it is fetched.
    open_world_hint=False,
)


@_surface_api_errors
async def search_threat_library(
    ctx: Context[ReaderFor, Any], query: str | None = None
) -> LibraryThreatMatches:
    """Search the shared catalog of library threats.

    The catalog is not per-organization: every organization reads the same rows,
    populated from installed packs. These are threat templates, not the threats
    recorded against any particular threat model.

    `query` matches a threat's name and description, and its taxonomy mappings — both
    the entry title and its identifier. Identifiers match in full: `CWE-20` returns the
    threats mapped to CWE-20 and not those mapped to CWE-200 or CWE-201. Everything
    else is a case-insensitive substring, so `injection` matches `SQL Injection`.

    Omitting `query` returns the whole catalog. It is a few dozen threats per installed
    pack, so that is affordable but not free.

    `matched` and `catalogSize` come back beside the rows. Read them for "how many"
    rather than counting the entries.
    """
    threats = [
        LibraryThreat.model_validate(row) for row in await _read(ctx).threat_library()
    ]

    if query is None:
        found = threats
    else:
        # An identifier is a name, not prose. Matching `CWE-20` as a substring returns
        # 17 rows where 9 are mapped to it, and the 8 extras are not near-misses a
        # caller can spot — CWE-200 is Information Exposure. This is the whole reason
        # the query is not forwarded to `?search=`, which is `icontains` and cannot be
        # told otherwise.
        identifier = query.casefold()
        found = [
            threat
            for threat in threats
            if _matches(query, threat.name, threat.description)
            or any(
                entry.external_id.casefold() == identifier
                or _matches(query, entry.title)
                for entry in threat.taxonomy_entries
            )
        ]

    return LibraryThreatMatches(
        matches=found, matched=len(found), catalog_size=len(threats)
    )


@_surface_api_errors
async def search_countermeasure_library(
    ctx: Context[ReaderFor, Any],
    query: str | None = None,
    control_function: str | None = None,
    control_nature: str | None = None,
    cost: Literal["low", "medium", "high"] | None = None,
) -> LibraryCountermeasureMatches:
    """Search the shared catalog of library countermeasures.

    These are control templates from installed packs, shared across every organization.
    They are not the countermeasures applied to any threat model, and carry no
    implementation status. `default_status` is the state a countermeasure starts in
    when it is applied.

    `query` matches the name and the description, so a control whose name does not
    mention the mechanism is still found when its description does. An empty result
    still does not prove no such control exists: narrow by `control_function`,
    `control_nature`, and `cost` instead, or omit `query` and read all of them. The
    catalog runs to tens of controls, not hundreds.

    `control_function` matches any entry in the countermeasure's `control_functions`
    list (e.g. `preventive`, `detective`, `corrective`). A single countermeasure can
    have multiple functions.

    `control_nature` is `technical`, `administrative`, or `physical`.

    `matched` and `catalogSize` come back beside the rows. Read them for "how many"
    rather than counting the entries.
    """
    countermeasures = [
        LibraryCountermeasure.model_validate(row)
        for row in await _read(ctx).countermeasure_library()
    ]
    found = [
        countermeasure
        for countermeasure in countermeasures
        if (
            query is None
            or _matches(query, countermeasure.name, countermeasure.description)
        )
        and (
            control_function is None
            or any(
                fn.casefold() == control_function.casefold()
                for fn in countermeasure.control_functions
            )
        )
        and (
            control_nature is None
            or countermeasure.control_nature.casefold() == control_nature.casefold()
        )
        and (cost is None or countermeasure.cost == cost)
    ]
    return LibraryCountermeasureMatches(
        matches=found, matched=len(found), catalog_size=len(countermeasures)
    )


@_surface_api_errors
async def search_component_library(
    ctx: Context[ReaderFor, Any],
    query: str | None = None,
    category: Literal[
        "process", "datastore", "external_human_actor", "external_system_actor"
    ]
    | None = None,
    kind: str | None = None,
) -> LibraryComponentMatches:
    """Search the shared catalog of library components.

    These are component templates from installed packs — the building blocks a system
    is drawn from — shared across every organization. They are not the components of
    any particular system.

    `query` matches the name, the component type, the provider, and the qualified slug,
    all as case-insensitive substrings. So `s3` finds `aws/s3`, and `database` finds
    every component typed as one.

    `category` is the role the component plays in a data flow diagram. `kind` is the
    CycloneDX asset type (`device`, `service`, `data-store`, ...), matched against the
    effective kind, which derives from the category when the pack declared none.
    Omitting every argument returns the whole catalog, which is the smallest of the
    three.

    `matched` and `catalogSize` come back beside the rows. Read them for "how many"
    rather than counting the entries.
    """
    components = [
        LibraryComponent.model_validate(row)
        for row in await _read(ctx).component_library()
    ]
    found = [
        component
        for component in components
        if (
            query is None
            or _matches(
                query,
                component.name,
                component.component_type,
                component.provider,
                component.qualified_slug or "",
            )
        )
        and (category is None or component.category == category)
        and (kind is None or component.effective_kind == kind)
    ]
    return LibraryComponentMatches(
        matches=found, matched=len(found), catalog_size=len(components)
    )


def environment_reader(access_token: AccessToken | None) -> PrecoglyReader:
    """The stdio reader: Precogly's REST API, with a token from the environment.

    `access_token` is always `None` here, because stdio has no request to carry one.
    It is in the signature because `ReaderFor` is what the lifespan holds either way.
    """
    return HTTPReader(_BASE_URL, http_client, os.environ.get("PRECOGLY_TOKEN", ""))


def build_server(
    *,
    reader_for: ReaderFor = environment_reader,
    auth: AuthSettings | None = None,
    token_verifier: TokenVerifier | None = None,
) -> MCPServer:
    """Assemble the server and register every tool on it.

    Named `server` rather than `mcp`: binding the name `mcp` would shadow the package
    this module imports from. The version is read from installed metadata rather than
    repeated here, so clients never display one that has drifted from pyproject.toml.

    `reader_for` reaches the tools through the lifespan, which is the only place a
    server-wide value can live: it is created once per process, while the reader it
    returns is per call, because the user is resolved per call.
    """

    @asynccontextmanager
    async def lifespan(_: MCPServer) -> AsyncGenerator[ReaderFor]:
        yield reader_for

    server = MCPServer(
        "precogly",
        version=version("precogly-mcp"),
        auth=auth,
        token_verifier=token_verifier,
        lifespan=lifespan,
    )
    server.add_tool(
        list_threat_models,
        title="List threat models",
        annotations=_LIST_ANNOTATIONS,
    )
    server.add_tool(
        search_threat_library,
        title="Search the threat library",
        annotations=_CATALOG_ANNOTATIONS,
    )
    server.add_tool(
        search_countermeasure_library,
        title="Search the countermeasure library",
        annotations=_CATALOG_ANNOTATIONS,
    )
    server.add_tool(
        search_component_library,
        title="Search the component library",
        annotations=_CATALOG_ANNOTATIONS,
    )
    return server


def asgi_app(
    *,
    reader_for: ReaderFor,
    token_verifier: TokenVerifier,
    issuer_url: str,
    resource_url: str,
    required_scopes: list[str] | None = None,
) -> Starlette:
    """Build the MCP endpoint for Precogly to mount.

    `reader_for` has no default, unlike on `build_server`. The stdio reader would type
    check here and fail on every call: it presents the caller's token to the REST API,
    and a token this endpoint accepts is audience-bound to this endpoint, so
    django-oauth-toolkit refuses it there. The mounting application has to supply a
    reader that does not go back out over HTTP.

    `resource_url` is the audience: the canonical URI a client names in its RFC 8707
    `resource` parameter, and the one the verifier must find on a token before
    accepting it. It is also what fixes where the protected-resource document is
    served — RFC 9728 puts it at `/.well-known/oauth-protected-resource` plus this
    URL's path, so both routes are registered at the origin root and the app has to
    be dispatched to from there rather than mounted under a prefix.

    `json_response` is what lets this run under Precogly's WSGI stack: every reply is
    a single JSON object, which the specification permits in place of an SSE stream.
    The cost is that nothing can stream — a tool cannot report progress while it
    works. No tool here does.

    `stateless_http` because the transport revision this targets has no protocol-level
    sessions to keep.
    """
    server = build_server(
        reader_for=reader_for,
        # Passed as strings, deliberately. `AuthSettings` sets
        # `url_preserve_empty_path` so a path-less issuer keeps its canonical form;
        # coercing to `AnyHttpUrl` here instead would apply pydantic's default
        # normalization and append a trailing slash, and RFC 8414 issuer comparison
        # is exact string comparison — the client would reject its own issuer.
        auth=AuthSettings(
            issuer_url=issuer_url,  # type: ignore[arg-type]
            resource_server_url=resource_url,  # type: ignore[arg-type]
            required_scopes=required_scopes or ["read"],
        ),
        token_verifier=token_verifier,
    )
    return server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
    )


def main() -> None:
    """Entry point for the `precogly-mcp` console script.

    Stdio, and so unauthorized: the token comes from `PRECOGLY_TOKEN`. Takes no
    arguments — the mounted transport is configured by Precogly, not from here.
    """
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
