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
# 2026-10-11 snapshot was taken (it was also the branch head that day).
# Decision D19: re-pin when 2.0 is final.
PINNED_COMMIT = "f6dcf4d33fecff511c21c4616a5a66d2b8134687"
PINNED_COMMIT_DATE = "2026-10-07"
SNAPSHOT_DATE = "2026-10-11"
SCHEMA_ID = "https://cyclonedx.org/schema/2.0/cyclonedx-2.0-bundled.schema.json"

SCHEMA_PATH = Path(__file__).resolve().parent / "cyclonedx-2.0-bundled.schema.json"


@cache
def load_schema() -> dict:
    """Return the parsed bundled schema. Parsed once; the file is 850 KB."""
    with SCHEMA_PATH.open(encoding="utf-8") as schema_file:
        return json.load(schema_file)
