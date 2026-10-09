"""Legacy format adapters.

`cyclonedx.py` and `tm_library.py` in this package are the pre-2.0 adapters.
They are switched off: nothing imports them, the views call
`apps.threat_models.tmbom` instead, and the files are listed for removal.
`base.py` stays for the adapter interface.
"""

from .base import BaseAdapter

__all__ = ["BaseAdapter"]
