"""Demo packs: the small packs bundled with the app for trying it out.

Their slugs start with `demo-` (demo-aws, demo-asvs). The full packs live in
precogly/library-packs, whose checks refuse that prefix, so the prefix alone
tells a demo pack from a full one.
"""

DEMO_PACK_SLUG_PREFIX = "demo-"


def is_demo_pack(pack_slug: str | None) -> bool:
    """True for a demo pack's slug."""
    return bool(pack_slug) and pack_slug.startswith(DEMO_PACK_SLUG_PREFIX)
