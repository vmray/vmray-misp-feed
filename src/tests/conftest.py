# pylint: disable=redefined-outer-name

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def data_dir():
    rel_path = Path("data")
    return Path(__file__).resolve().parent / rel_path
