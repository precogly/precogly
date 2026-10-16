"""Stable bom-refs (plan section 9.2).

A ref is derived from the row's id, so it is the same on every export and
needs no column. A ref that arrived on import is kept in
``format_metadata["cyclonedx"]["bom_ref"]`` at import time and re-emitted as
it came, which is what keeps other documents' BOM-Links and passthrough
sections resolving. Nothing is written to rows during export (S1).

If a derived ref equals a stored ref of another row in the same model (a file
from another installation can carry ``scenario-812`` while a local row has id
812), the derived one gets a fixed suffix for this export. The same holds for
refs defined inside kept passthrough content (an attack tree node, say),
which the export writes back as they came (S1, R48).
"""

from dataclasses import dataclass, field

LOCAL_SUFFIX = "-local"


def stored_ref(row) -> str | None:
    """The bom-ref an imported row arrived with, if any."""
    metadata = getattr(row, "format_metadata", None) or {}
    value = (metadata.get("cyclonedx") or {}).get("bom_ref")
    return value if isinstance(value, str) and value else None


def remember_ref(row, bom_ref: str) -> None:
    """Record an imported bom-ref on a row's format_metadata (import side)."""
    if not bom_ref:
        return
    metadata = dict(getattr(row, "format_metadata", None) or {})
    cyclonedx = dict(metadata.get("cyclonedx") or {})
    cyclonedx["bom_ref"] = bom_ref
    metadata["cyclonedx"] = cyclonedx
    row.format_metadata = metadata


def derived_ref(kind: str, row_id) -> str:
    return f"{kind}-{row_id}"


@dataclass
class RefRegistry:
    """Hands out one ref per row for one export, unique across the document."""

    _stored: set[str] = field(default_factory=set)
    _kept: set[str] = field(default_factory=set)
    _issued: dict[tuple[str, int], str] = field(default_factory=dict)
    _used: set[str] = field(default_factory=set)

    def reserve_stored(self, rows) -> None:
        """Note the refs that imported rows carry, before any ref is issued."""
        for row in rows:
            value = stored_ref(row)
            if value:
                self._stored.add(value)

    def reserve_kept(self, bom_refs) -> None:
        """Note the refs kept passthrough content defines, before any is issued.

        Call after ``reserve_stored``: a ref a row of this model carries is
        written by that row, not by the kept content (a blueprint's kept
        actors include the ones that became personas, for instance).
        """
        self._kept.update(
            ref
            for ref in bom_refs
            if isinstance(ref, str) and ref and ref not in self._stored
        )

    def ref(self, kind: str, row) -> str:
        """The ref for ``row``: its stored ref, else ``<kind>-<id>``, de-clashed."""
        key = (kind, row.pk)
        if key in self._issued:
            return self._issued[key]
        candidate = stored_ref(row) or derived_ref(kind, row.pk)
        if candidate in self._used or (
            candidate in (self._stored | self._kept) and stored_ref(row) != candidate
        ):
            candidate = f"{derived_ref(kind, row.pk)}{LOCAL_SUFFIX}"
            while candidate in self._used:
                candidate += LOCAL_SUFFIX
        self._issued[key] = candidate
        self._used.add(candidate)
        return candidate

    def is_issued(self, bom_ref: str) -> bool:
        """Whether ``bom_ref`` names something this export has emitted."""
        return bom_ref in self._used

    def will_resolve(self, bom_ref: str) -> bool:
        """Whether ``bom_ref`` will name something in the finished document:
        issued here, or defined by kept content written back later. A ref
        kept on a row (``extra_applies_to`` and the like) is re-emitted only
        when this holds."""
        return bom_ref in self._used or bom_ref in self._kept

    def fixed(self, bom_ref: str) -> str:
        """Claim a ref that is not tied to a row (the system component, say)."""
        candidate = bom_ref
        while candidate in self._used or candidate in self._kept:
            candidate += LOCAL_SUFFIX
        self._used.add(candidate)
        return candidate
