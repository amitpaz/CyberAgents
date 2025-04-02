"""Test suite runner that discovers and executes all agent-specific tests."""

import pytest
import os
import sys

# Add project root to path to ensure agents module is discoverable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Note: Pytest typically discovers tests automatically if run from the root
# or if the 'agents' directory is configured as a test source.
# This file primarily serves as an explicit entry point if needed or 
# for potentially adding suite-level fixtures or configurations later.

def test_placeholder_for_agent_suite():
    """This placeholder ensures the file is picked up by pytest.
    Actual tests are discovered within the agents directory.
    """
    # We expect pytest to find tests in agents/**/test_*.py
    # If pytest is run from the root directory, it should find these automatically.
    # Example command from root: poetry run pytest tests/test_agent_suite.py agents/
    pass

# You can add suite-level fixtures here if needed, e.g.:
# @pytest.fixture(scope="session", autouse=True)
# def setup_global_resources():
#     print("\nSetting up resources for the agent test suite...")
#     yield
#     print("\nTearing down resources for the agent test suite...") 