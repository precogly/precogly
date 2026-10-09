"""CycloneDX 2.0 TM-BOM adapter package.

Built against the pinned schema in ``tmbom/schema``. Every document this package
emits validates against that schema with zero errors; see ``validation``.

The package replaces ``adapters/cyclonedx.py`` slice by slice (plan section 9).
It lives beside ``adapters/`` rather than inside it because a package named
``cyclonedx`` cannot coexist with the old module of the same name.
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
