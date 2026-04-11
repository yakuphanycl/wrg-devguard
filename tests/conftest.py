from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_path():
    with tempfile.TemporaryDirectory(prefix="wrg_devguard_test_") as td:
        yield Path(td)
