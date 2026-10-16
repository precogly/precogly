"""Spec values a row holds only in part, kept at import and written back on export.

Each value is kept under the row's ``format_metadata["cyclonedx"]`` and is
written back only while the row still holds what it was imported as, so an
edit in Precogly wins over the kept value:

- ``owner``: a party that is no member of the organization (a persona, an
  organization, an unknown person). Written back while the row has no owner;
  setting or clearing the owner in Precogly drops it
  (``apps.threats.services.forget_kept_owner``).
- ``effectiveness``: the spec object with its ``rating``. Written back while
  the row's percentage is the imported one.
- ``domain_details``: a risk domain's ``priority`` and ``description``, by
  domain type. Written back for the domains the risk still has. A custom
  domain is kept whole (``extra_domains``) and always written back.
"""

import copy


def owner_to_keep(raw, parties_by_ref: dict):
    """The owner to keep when it matched no member, else None.

    A ref to a declared party is kept as an inline copy without its
    ``bom-ref``: the export declares its own parties, not the imported ones.
    A ref that names no declared party is kept as the ref.
    """
    if isinstance(raw, str):
        party = parties_by_ref.get(raw)
        if isinstance(party, dict):
            inline = copy.deepcopy(party)
            inline.pop("bom-ref", None)
            return inline
        return raw or None
    if isinstance(raw, dict):
        return copy.deepcopy(raw)
    return None


def kept_owner_entry(row, refs):
    """The kept owner to write, or None; a kept ref only when it resolves."""
    kept = ((row.format_metadata or {}).get("cyclonedx") or {}).get("owner")
    if isinstance(kept, dict):
        return copy.deepcopy(kept)
    if isinstance(kept, str) and refs.will_resolve(kept):
        return kept
    return None


def effectiveness_to_keep(raw):
    """The spec object when it carries more than the percentage, else None."""
    if isinstance(raw, dict) and set(raw) - {"percentage"}:
        return copy.deepcopy(raw)
    return None


def effectiveness_entry(percentage, row):
    """The ``effectiveness`` object to write, or None.

    The kept object (with its ``rating``) is written while the row's
    percentage equals the imported one; after an edit only the percentage is.
    """
    kept = ((row.format_metadata or {}).get("cyclonedx") or {}).get("effectiveness")
    if isinstance(kept, dict) and kept.get("percentage") == percentage:
        return copy.deepcopy(kept)
    if percentage is not None:
        return {"percentage": percentage}
    return None


def domain_details_to_keep(raw_domains, type_of) -> dict:
    """``{domain type: {priority, description}}`` for the domains that carry them."""
    details = {}
    for domain in raw_domains or []:
        if not isinstance(domain, dict):
            continue
        extra = {
            key: copy.deepcopy(domain[key])
            for key in ("priority", "description")
            if key in domain
        }
        name = type_of(domain.get("type"))
        if extra and name and name not in details:
            details[name] = extra
    return details
