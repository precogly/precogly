"""Errors raised to the agent's code, written for the agent to act on."""

from precogly_mcp.scope_challenge import InsufficientScope


class APIError(Exception):
    """A request the agent's code made was refused or failed."""


class InsufficientScopeError(InsufficientScope, APIError):
    """A request the agent's code made needs a scope the connection was not granted.

    An `APIError` to the agent's code; an `InsufficientScope` to `execute`, which turns
    it into a scope challenge.
    """
