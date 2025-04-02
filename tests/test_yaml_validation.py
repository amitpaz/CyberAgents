"""Test suite for YAML validation."""

import pytest
import os
import yaml
from scripts.validate_yaml import validate_yaml, load_yaml, load_schema


def validate_yaml_file(yaml_file, schema_file="schemas/agent_schema.yaml"):
    """Helper function to validate a YAML file against a schema."""
    try:
        data = load_yaml(yaml_file)
        schema = load_schema(schema_file)
        is_valid, error = validate_yaml(data, schema)
        return is_valid
    except Exception as e:
        print(f"Error validating {yaml_file}: {str(e)}")
        return False


def test_agent_yaml_schema():
    """Test that all agent YAML files conform to the schema.

    This ensures that:
    1. All agent definitions follow the required structure
    2. Required fields are present
    3. Field types and formats are correct
    4. Dependencies and relationships are properly defined
    """
    agents_dir = "agents"
    if not os.path.exists(agents_dir):
        pytest.skip("No agents directory found")
    for agent_dir in os.listdir(agents_dir):
        agent_yaml = os.path.join(agents_dir, agent_dir, "agent.yaml")
        if os.path.exists(agent_yaml):
            assert validate_yaml_file(
                agent_yaml
            ), f"Agent YAML validation failed for {agent_yaml}"


def test_workflow_yaml_schema():
    """Test that all workflow YAML files conform to the schema.

    This ensures that:
    1. All workflow definitions follow the required structure
    2. Steps are properly sequenced and defined
    3. Dependencies between steps are valid
    4. Input/output relationships are correctly specified
    5. Error handling and retry logic is properly configured
    """
    workflows_dir = "workflows"
    if not os.path.exists(workflows_dir):
        pytest.skip("No workflows directory found")
    for workflow_file in os.listdir(workflows_dir):
        if workflow_file.endswith(".yaml"):
            workflow_yaml = os.path.join(workflows_dir, workflow_file)
            assert validate_yaml_file(
                workflow_yaml, "schemas/workflow_schema.yaml"
            ), f"Workflow YAML validation failed for {workflow_yaml}"


def test_validate_yaml_file():
    """Test YAML file validation."""
    # Test with a valid YAML file
    valid_yaml = """
    name: Test
    version: 1.0.0
    """
    with open("test_valid.yaml", "w") as f:
        f.write(valid_yaml)
    assert validate_yaml_file("test_valid.yaml") is True
    os.remove("test_valid.yaml")

    # Test with an invalid YAML file
    invalid_yaml = """
    name: Test
    version: 1.0.0
    invalid: : :
    """
    with open("test_invalid.yaml", "w") as f:
        f.write(invalid_yaml)
    assert validate_yaml_file("test_invalid.yaml") is False
    os.remove("test_invalid.yaml")
