"""Import: a CycloneDX 2.0 TM-BOM document into a new threat model."""

from .document import ImportContext, TmBomImportError, import_document

__all__ = ["ImportContext", "TmBomImportError", "import_document"]
