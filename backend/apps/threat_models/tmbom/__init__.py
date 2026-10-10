"""CycloneDX 2.0 TM-BOM adapter package.

Built against the pinned schema in ``tmbom/schema``. Every document this package
emits validates against that schema with zero errors; see ``validation``.

It replaced the pre-2.0 ``adapters/cyclonedx.py``, which has been removed. It
lives beside ``adapters/`` because the two could not coexist while the old
module was there (D-B1); moving it under ``adapters/`` is a possible follow-up.
"""

from .exporter import export_threat_model
from .importer import TmBomImportError, import_document


class TmBomAdapter:
    """The entry point the views use: export a model, import a document."""

    def export_data(self, threat_model, warnings: list | None = None) -> dict:
        return export_threat_model(threat_model, warnings)

    def import_data(self, document, organization, user):
        return import_document(document, organization, user)


__all__ = ["TmBomAdapter", "TmBomImportError", "export_threat_model", "import_document"]
