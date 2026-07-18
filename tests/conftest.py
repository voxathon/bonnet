import pytest
import tempfile
import shutil
import os

@pytest.fixture
def temp_dir():
    """Provides a temporary directory local to the working directory for test data."""
    base = os.path.join(os.getcwd(), ".pytest_tmp")
    os.makedirs(base, exist_ok=True)
    test_dir = tempfile.mkdtemp(prefix="bonnet_test_", dir=base)
    yield test_dir
    shutil.rmtree(test_dir, ignore_errors=True)
