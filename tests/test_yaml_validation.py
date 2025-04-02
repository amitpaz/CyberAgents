"""Tests for YAML validation functionality."""

from scripts.validate_yaml import (
    load_yaml,
    validate_agent_yaml,
    validate_schema,
    validate_yaml_file,
)


def test_load_yaml(tmp_path):
    """Test loading a YAML file."""
    yaml_content = """
    id: test_agent
    name: Test Agent
    description: A test agent
    tools: []
    """
    yaml_file = tmp_path / "test.yaml"
    yaml_file.write_text(yaml_content)
    data = load_yaml(str(yaml_file))
    assert data["id"] == "test_agent"
    assert data["name"] == "Test Agent"
    assert data["description"] == "A test agent"
    assert data["tools"] == []


def test_validate_schema():
    """Test schema validation."""
    schema = {
        "type": "object",
        "required": ["id", "name"],
        "properties": {"id": {"type": "string"}, "name": {"type": "string"}},
    }
    data = {"id": "test", "name": "Test"}
    assert validate_schema(data, schema) is True


def test_validate_agent_yaml(tmp_path):
    """Test agent YAML validation."""
    yaml_content = """
    id: test_agent
    name: Test Agent
    description: A test agent
    tools: []
    """
    yaml_file = tmp_path / "test.yaml"
    yaml_file.write_text(yaml_content)
    assert validate_agent_yaml(str(yaml_file)) is True


def test_validate_yaml_file(tmp_path):
    """Test YAML file validation against schema."""
    yaml_content = """
    id: test_agent
    name: Test Agent
    """
    schema_content = """
    type: object
    required: [id, name]
    properties:
      id:
        type: string
      name:
        type: string
    """
    yaml_file = tmp_path / "test.yaml"
    schema_file = tmp_path / "schema.yaml"
    yaml_file.write_text(yaml_content)
    schema_file.write_text(schema_content)
    assert validate_yaml_file(str(yaml_file), str(schema_file)) is True
