import os
import tempfile

# Ensure ACCOUNT_SECRET is set before any service module is imported at module level.
# Without this, importing services.account.app or services.inference.app raises RuntimeError.
if "ACCOUNT_SECRET" not in os.environ:
    os.environ["ACCOUNT_SECRET"] = "test-secret"

import pytest


@pytest.fixture
def tmp_deployment_repo(tmp_path):
    """Create a temporary deployment repo directory."""
    return tmp_path
