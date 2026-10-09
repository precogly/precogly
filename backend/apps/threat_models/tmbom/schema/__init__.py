"""The pinned CycloneDX 2.0 bundled schema.

``cyclonedx-2.0-bundled.schema.json`` is a byte-for-byte copy of
``schema/2.0/cyclonedx-2.0-bundled.schema.json`` from the ``2.0-dev`` branch of
https://github.com/CycloneDX/specification at ``PINNED_COMMIT``. Re-pin by
replacing the file and updating the two constants; the spec value tests in
``tmbom`` then show exactly what changed.
"""

import json
from functools import cache
from pathlib import Path

# The last commit on 2.0-dev that changed the bundled schema before the
# 2026-10-01 snapshot was taken (the file is identical at every later commit up
# to and including ad519021 of 2026-10-01). Decision D19: re-pin when 2.0 is final.
PINNED_COMMIT = "be4b15742e4b3b9eade95c15b5c590d4b8c83338"
PINNED_COMMIT_DATE = "2026-09-24"
SNAPSHOT_DATE = "2026-10-01"
SCHEMA_ID = "https://cyclonedx.org/schema/2.0/cyclonedx-2.0-bundled.schema.json"

SCHEMA_PATH = Path(__file__).resolve().parent / "cyclonedx-2.0-bundled.schema.json"


@cache
def load_schema() -> dict:
    """Return the parsed bundled schema. Parsed once; the file is 850 KB."""
    with SCHEMA_PATH.open(encoding="utf-8") as schema_file:
        return json.load(schema_file)
