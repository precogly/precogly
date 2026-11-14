"""Cut a JSON value to fit a character budget while keeping it valid JSON.

The largest values shrink first, lists keep whole items from the start, and every
cut leaves a `--- TRUNCATED ---` marker: a clipped string ends with
`--- TRUNCATED --- <n> chars`, a clipped list ends with a
`--- TRUNCATED --- <n> more items` element, and an object that lost entries gains a
`"--- TRUNCATED ---"` entry naming them.

Ported from Cloudflare's MCP server, `src/truncate.ts` at
https://github.com/cloudflare/mcp/blob/e8bc56f8638bc8ee6b6a2ccc1541b7fab46187e2/src/truncate.ts
(Apache-2.0), itself adapted from `@cloudflare/codemode`. Changes: sizes are measured
with `dumps`, the serializer the result is returned with, so the two cannot
disagree; and `fit` handles a top-level scalar too long for the budget, which the
original returns whole.
"""

from __future__ import annotations

import json
from typing import Any

MARKER = "--- TRUNCATED ---"

# The least a string or list is worth keeping at. A value that would get fewer
# characters than this is dropped in favour of its siblings rather than reduced to a
# bare marker. Cloudflare's value.
MIN_SLOT = 128


def dumps(value: Any) -> str:
    """Compact JSON: what every size below measures, and what the caller returns."""
    return json.dumps(value, separators=(",", ":"), allow_nan=False)


def fit(value: Any, max_chars: int) -> Any:
    """`value` cut so `dumps` of it is at most `max_chars` (at least 2) characters.

    `value` must already be plain JSON: dicts with string keys, lists, strings,
    numbers, booleans and `None`.
    """
    result = _shrink(value, max_chars)
    # Only a scalar is returned whole by `_shrink`; a number thousands of digits
    # long is the one way to get here.
    if _size(result) > max_chars:
        result = _shrink_string(dumps(value), max_chars)
    return result


# Every `_shrink*` returns a value whose serialization fits the budget it was given,
# provided the budget can hold an empty container (2 characters). A container gives
# each child at least its floor, then shares what is left by water-filling: small
# children keep their full size and the largest absorb the cut. Children are dropped
# only when their floors cannot fit. Lists drop from the tail, since order carries
# meaning; objects drop their largest values first, since every key is meaningful.


def _size(value: Any) -> int:
    return len(dumps(value))


def _skeleton(count: int) -> int:
    """Characters a container spends on brackets and commas for `count` children."""
    return 2 + max(0, count - 1)


def _key_cost(key: str) -> int:
    """Characters an object entry spends on its quoted key and colon."""
    return _size(key) + 1


def _shrinkable(value: Any) -> bool:
    """Only strings and containers can give up characters; scalars are atomic."""
    return isinstance(value, str | list | dict)


def _floor_size(value: Any, max_chars: int) -> int:
    """The least budget `value` is kept at when room is short.

    A scalar must fit whole. The floor never exceeds half the container's own
    budget, so a tiny budget still keeps something rather than nothing.
    """
    full = _size(value)
    if not _shrinkable(value):
        return full
    return min(full, MIN_SLOT, max(2, max_chars // 2))


def _key_floor(value: Any, max_chars: int) -> int:
    """The least budget that keeps every object key inside `value`.

    Strings and lists inside may still be clipped to their floor, but no object
    loses an entry.
    """
    if not isinstance(value, dict):
        return _floor_size(value, max_chars)
    return _skeleton(len(value)) + sum(
        _key_cost(key) + _key_floor(item, max_chars) for key, item in value.items()
    )


def _shrink(value: Any, max_chars: int) -> Any:
    if _size(value) <= max_chars:
        return value
    if isinstance(value, str):
        return _shrink_string(value, max_chars)
    if isinstance(value, list):
        return _shrink_list(value, max_chars)
    if isinstance(value, dict):
        return _shrink_object(value, max_chars)
    return value


def _shrink_string(value: str, max_chars: int) -> str:
    suffix = f" {MARKER} {len(value):,} chars"
    keep = max(0, max_chars - len(suffix) - 2)
    out = value[:keep] + suffix
    # Escapes inflate the serialized form; back off until it fits.
    while keep > 0 and _size(out) > max_chars:
        keep = max(0, keep - (_size(out) - max_chars))
        out = value[:keep] + suffix
    # No room for a prefix and the size note: keep as much of the marker as fits.
    return out if _size(out) <= max_chars else MARKER[: max(0, max_chars - 2)]


def _allocate(sizes: list[int], floors: list[int], available: int) -> list[int]:
    """Split `available` characters across children.

    Each child gets its floor, then the rest is water-filled over what each still
    wants, smallest want first, so every child either reaches its full size or takes
    an equal share of what is left. Requires `available >= sum(floors)`.
    """
    allocation = list(floors)
    wants = [full - floor for full, floor in zip(sizes, floors, strict=True)]
    remaining = available - sum(floors)
    count = len(wants)
    for i in sorted(range(len(wants)), key=lambda i: wants[i]):
        extra = min(wants[i], remaining // count)
        allocation[i] += extra
        remaining -= extra
        count -= 1
    return allocation


def _list_marker(dropped: int) -> str:
    return f"{MARKER} {dropped:,} more items"


def _shrink_list(items: list[Any], max_chars: int) -> list[Any]:
    # Items keep every key, so a list of records keeps whole records from the start
    # rather than every record cut down to a few fields.
    floors = [_key_floor(item, max_chars) for item in items]

    keep = len(items)
    if sum(floors) + _skeleton(keep) > max_chars:
        # Keep the longest prefix whose floors fit beside a tail marker, sized for
        # the largest possible count so the real one always fits.
        used = _skeleton(0) + _size(_list_marker(len(items))) + 1
        keep = 0
        while keep < len(items) and used + floors[keep] + 1 <= max_chars:
            used += floors[keep] + 1
            keep += 1
        # The next item cannot keep all its keys. Keep it cut down anyway when
        # nothing else fit or a quarter of the budget would otherwise go unused.
        if keep < len(items):
            room = max_chars - used - 1
            cut_down = _floor_size(items[keep], max_chars)
            if (keep == 0 or room >= max_chars / 4) and cut_down <= room:
                floors[keep] = cut_down
                keep += 1

    kept = items[:keep]
    dropped = len(items) - keep
    tail = _size(_list_marker(dropped)) + (1 if keep > 0 else 0) if dropped else 0
    allocation = _allocate(
        [_size(item) for item in kept],
        floors[:keep],
        max_chars - _skeleton(keep) - tail,
    )
    out = [_shrink(item, share) for item, share in zip(kept, allocation, strict=True)]
    if dropped and _size([*out, _list_marker(dropped)]) <= max_chars:
        out.append(_list_marker(dropped))
    return out


def _shrink_object(value: dict[str, Any], max_chars: int) -> dict[str, Any]:
    entries = list(value.items())
    value_sizes = [_size(item) for _, item in entries]

    # Every key fits: keep them all and share the rest.
    key_floors = [_key_floor(item, max_chars) for _, item in entries]
    fixed = _skeleton(len(entries)) + sum(_key_cost(key) for key, _ in entries)
    if fixed + sum(key_floors) <= max_chars:
        allocation = _allocate(value_sizes, key_floors, max_chars - fixed)
        return {
            key: _shrink(item, share)
            for (key, item), share in zip(entries, allocation, strict=True)
        }

    # The marker entry must not shadow a real key.
    marker_key = MARKER
    while marker_key in value:
        marker_key += " "
    floors = [_key_cost(key) + _floor_size(item, max_chars) for key, item in entries]

    def note_floor(chars: int) -> int:
        return min(chars, MIN_SLOT, max(2, max_chars // 2))

    # Drop the largest values first, only until the rest fit at their floor. Costs
    # are tracked incrementally so a wide object stays linear in its key count.
    by_value_size = sorted(range(len(entries)), key=lambda i: -value_sizes[i])
    dropped: set[int] = set()
    present = len(entries)
    floors_sum = sum(floors)
    names_length = 0

    def note_length() -> int:
        prefix = f"{len(dropped):,} keys omitted: "
        return len(prefix) + names_length + 2 * (len(dropped) - 1)

    def cost() -> int:
        marker = _key_cost(marker_key) + note_floor(note_length() + 2) if dropped else 0
        return _skeleton(present + (1 if dropped else 0)) + floors_sum + marker

    for i in by_value_size:
        if cost() <= max_chars:
            break
        dropped.add(i)
        present -= 1
        floors_sum -= floors[i]
        names_length += _size(entries[i][0]) - 2

    kept = [entry for i, entry in enumerate(entries) if i not in dropped]
    omitted = [entries[i][0] for i in sorted(dropped)]
    note = f"{len(omitted):,} keys omitted: {', '.join(omitted)}"
    if cost() > max_chars:
        # Not even the marker fits at its floor: keep as much of it as there is
        # room for, or nothing.
        room = max_chars - 2 - _key_cost(marker_key)
        return {marker_key: _shrink(note, room)} if room >= 2 else {}

    entries_out = [*kept, (marker_key, note)] if omitted else kept
    values = [item for _, item in entries_out]
    # The note is shrunk like any other value, so it can never overshoot.
    allocation = _allocate(
        [_size(item) for item in values],
        [_floor_size(item, max_chars) for item in values],
        max_chars
        - _skeleton(len(entries_out))
        - sum(_key_cost(key) for key, _ in entries_out),
    )
    return {
        key: _shrink(item, share)
        for (key, item), share in zip(entries_out, allocation, strict=True)
    }
