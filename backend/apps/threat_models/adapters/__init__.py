"""Format adapter interface.

The pre-2.0 CycloneDX and TM-Library adapters were removed; the TM-BOM adapter
is `apps.threat_models.tmbom`. `base.py` keeps the adapter interface.
"""

from .base import BaseAdapter

__all__ = ["BaseAdapter"]
