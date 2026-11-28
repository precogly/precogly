"""Settings shared by every backend test."""

import pytest


@pytest.fixture(autouse=True)
def pack_catalog_off(settings):
    """No test reaches the real pack catalog on GitHub.

    The default PACK_CATALOG_URL follows the latest library-packs release, so
    without this any test that lists, previews or validates a pack would make a
    network call. A test that needs a catalog sets its own address and
    replaces requests.get with a fake response.

    Set the address in setUp (self.enterContext(override_settings(...))) or on
    the test method. A class-level @override_settings is applied before this
    fixture runs, so this fixture would switch the catalog off again.
    """
    settings.PACK_CATALOG_URL = ""
