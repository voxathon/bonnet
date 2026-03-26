import pytest
import tempfile
import shutil
import os

@pytest.fixture
def temp_dir():
    """Provides a temporary directory local to the working directory for test data."""
    test_dir = tempfile.mkdtemp(prefix="bonnet_test_", dir=os.getcwd())
    yield test_dir
    shutil.rmtree(test_dir, ignore_errors=True)
