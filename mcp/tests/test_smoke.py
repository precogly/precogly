"""Smoke tests for precogly_mcp."""

from __future__ import annotations

import precogly_mcp


def test_version_is_set() -> None:
    assert precogly_mcp.__version__
