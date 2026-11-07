"""Errors raised to the agent's code, written for the agent to act on."""


class APIError(Exception):
    """A request the agent's code made was refused or failed."""
