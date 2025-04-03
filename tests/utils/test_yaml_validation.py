"""Tests for YAML validation functionality."""

import pytest # Import pytest
import os # Import os
from scripts.validate_yaml import (
    load_yaml,
    validate_agent_yaml,
    validate_schema,
    validate_yaml_file,
)

# Get the absolute path to the schema file
SCHEMA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'schemas'))
AGENT_SCHEMA_PATH = os.path.join(SCHEMA_DIR, 'agent_schema.yaml')

def test_load_yaml(tmp_path):
    """Test loading a YAML file."""
    # Use a structure that matches the *new* simplified schema for consistency
    yaml_content = """
    role: Test Role
    goal: Test Goal
    backstory: Test Backstory
    tools: []
    allow_delegation: false
    verbose: true
    """
    yaml_file = tmp_path / "test.yaml"
    yaml_file.write_text(yaml_content)
    data = load_yaml(str(yaml_file))
    assert data["role"] == "Test Role"
    assert data["goal"] == "Test Goal"
    assert data["allow_delegation"] is False
    assert data["tools"] == []


def test_validate_schema():
    """Test basic schema validation logic."""
    schema = {
        "type": "object",
        "required": ["role", "goal"],
        "properties": {"role": {"type": "string"}, "goal": {"type": "string"}},
        "additionalProperties": False
    }
    valid_data = {"role": "test", "goal": "Test"}
    invalid_data_missing = {"role": "test"}
    invalid_data_extra = {"role": "test", "goal": "Test", "extra": "field"}
    
    assert validate_schema(valid_data, schema) is True, "Valid data failed schema check"
    assert validate_schema(invalid_data_missing, schema) is False, "Missing required field passed schema check"
    assert validate_schema(invalid_data_extra, schema) is False, "Extra property passed schema check"


def test_validate_agent_yaml_valid(tmp_path):
    """Test agent YAML validation with valid data against the actual schema."""
    # Ensure the schema file exists
    if not os.path.exists(AGENT_SCHEMA_PATH):
        pytest.skip(f"Agent schema not found at {AGENT_SCHEMA_PATH}")
        
    # Valid content according to the simplified schema
    yaml_content = """
    role: Valid Role
    goal: Valid Goal
    backstory: |
      Valid backstory.
    tools:
      - tool1
      - tool2
    allow_delegation: true
    verbose: true
    memory: false
    """
    yaml_file = tmp_path / "valid_agent.yaml"
    yaml_file.write_text(yaml_content)
    # Pass the actual schema path to the validation function
    assert validate_agent_yaml(str(yaml_file)) is True, "Valid agent YAML failed validation"

def test_validate_agent_yaml_invalid(tmp_path):
    """Test agent YAML validation with invalid data against the actual schema."""
    # Ensure the schema file exists
    if not os.path.exists(AGENT_SCHEMA_PATH):
        pytest.skip(f"Agent schema not found at {AGENT_SCHEMA_PATH}")

    # Invalid content (missing 'goal')
    yaml_content_missing = """
    role: Invalid Role
    backstory: Invalid backstory.
    tools: []
    allow_delegation: false
    """
    # Invalid content (extra field)
    yaml_content_extra = """
    role: Invalid Role
    goal: Invalid Goal
    backstory: Invalid backstory.
    tools: []
    allow_delegation: false
    extra_field: some_value 
    """
    
    yaml_file_missing = tmp_path / "invalid_agent_missing.yaml"
    yaml_file_missing.write_text(yaml_content_missing)
    yaml_file_extra = tmp_path / "invalid_agent_extra.yaml"
    yaml_file_extra.write_text(yaml_content_extra)

    assert validate_agent_yaml(str(yaml_file_missing)) is False, "Invalid agent YAML (missing field) passed validation"
    assert validate_agent_yaml(str(yaml_file_extra)) is False, "Invalid agent YAML (extra field) passed validation"

# Keep test_validate_yaml_file if validate_yaml_file is still used elsewhere
# If validate_agent_yaml is the primary entrypoint, this might be redundant
def test_validate_yaml_file(tmp_path):
    """Test generic YAML file validation against a schema."""
    yaml_content = """
    role: Test Role
    goal: Test Goal
    """
    schema_content = """
    type: object
    required: [role, goal]
    properties:
      role: { type: string }
      goal: { type: string }
    additionalProperties: false
    """
    yaml_file = tmp_path / "test.yaml"
    schema_file = tmp_path / "schema.yaml"
    yaml_file.write_text(yaml_content)
    schema_file.write_text(schema_content)
    assert validate_yaml_file(str(yaml_file), str(schema_file)) is True
