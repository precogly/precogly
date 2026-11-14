"""`fit` cuts a JSON value to a budget and keeps it valid JSON."""

from __future__ import annotations

import json
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from precogly_mcp.truncate import MARKER, dumps, fit

# Any plain JSON value: what a search can return once it has been through `dumps`.
JSON = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(),
    lambda children: st.lists(children) | st.dictionaries(st.text(), children),
    max_leaves=40,
)


@given(JSON, st.integers(min_value=2, max_value=2_000))
def test_the_result_always_fits_the_budget(value: Any, budget: int) -> None:
    assert len(dumps(fit(value, budget))) <= budget


@given(JSON, st.integers(min_value=2, max_value=2_000))
def test_a_value_that_fits_is_returned_unchanged(value: Any, budget: int) -> None:
    if len(dumps(value)) <= budget:
        assert fit(value, budget) == value


def test_a_list_keeps_whole_records_from_the_start() -> None:
    records = [{"path": f"/api/{i}/", "method": "get"} for i in range(100)]

    out = fit(records, 300)

    *kept, marker = out
    assert kept == records[: len(kept)]
    assert marker == f"{MARKER} {100 - len(kept)} more items"


def test_an_object_clips_a_large_value_but_keeps_its_key() -> None:
    out = fit({"summary": "List zones", "description": "x" * 5_000}, 200)

    assert out["summary"] == "List zones"
    assert out["description"].endswith(f"{MARKER} 5,000 chars")


def test_keys_are_cut_at_the_level_that_cannot_hold_them() -> None:
    # `responses` itself shrinks to its floor and keeps its place; its own 300 keys
    # are what cannot all fit, so the cut and its marker are one level down.
    operation = {"summary": "List zones", "responses": {str(i): i for i in range(300)}}

    out = fit(operation, 200)

    assert out["summary"] == "List zones"
    assert MARKER not in out
    assert "keys omitted" in out["responses"][MARKER]


def test_an_object_with_too_many_keys_names_the_ones_it_dropped() -> None:
    value = {f"key{i}": "x" * 500 for i in range(20)}

    out = fit(value, 300)

    kept = [key for key in out if key != MARKER]
    assert out[MARKER].startswith(f"{20 - len(kept)} keys omitted: ")
    assert set(kept) < set(value)


def test_a_long_string_is_clipped_with_its_length() -> None:
    out = fit("y" * 1_000, 100)

    assert out.startswith("yyy")
    assert out.endswith(f"{MARKER} 1,000 chars")


def test_a_huge_number_becomes_a_clipped_string() -> None:
    # The original returns a scalar whole, so a 501-digit number would overshoot.
    # (Past 4,300 digits Python cannot serialize an int at all; `search` reports
    # that as a result that is not JSON before `fit` is reached.)
    out = fit(10**500, 100)

    assert isinstance(out, str)
    assert len(json.dumps(out)) <= 100
