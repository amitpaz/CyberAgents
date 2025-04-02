"""YAML validation script for agent configurations."""

import os
import sys
from typing import Any, Dict, List

import yaml
from jsonschema import ValidationError, validate


def load_yaml(file_path: str) -> Dict[str, Any]:
    """Load and parse a YAML file.

    Args:
        file_path: Path to the YAML file

    Returns:
        Dictionary containing the parsed YAML content
    """
    with open(file_path, "r") as f:
        return yaml.safe_load(f)


def load_schema(schema_path: str) -> Dict[str, Any]:
    """Load and parse a schema file.

    Args:
        schema_path: Path to the schema file

    Returns:
        Dictionary containing the parsed schema
    """
    with open(schema_path, "r") as f:
        return yaml.safe_load(f)


def validate_schema(data: Dict[str, Any], schema: Dict[str, Any]) -> bool:
    """Validate data against a JSON schema.

    Args:
        data: Dictionary to validate
        schema: JSON schema to validate against

    Returns:
        True if validation passes, False otherwise
    """
    try:
        validate(instance=data, schema=schema)
        return True
    except ValidationError as e:
        print(f"Validation error: {e}")
        return False


def get_agent_properties() -> Dict[str, Any]:
    """Get the properties schema for agent configuration.

    Returns:
        Dictionary containing the properties schema
    """
    return {
        "name": {"type": "string"},
        "uuid": {"type": "string"},
        "responsibilities": {"type": "string"},
    }


def get_tool_properties() -> Dict[str, Any]:
    """Get the properties schema for tool configuration.

    Returns:
        Dictionary containing the properties schema
    """
    return {"name": {"type": "string"}, "type": {"type": "string"}}


def get_array_schema(item_type: str = "string") -> Dict[str, Any]:
    """Get a schema for an array of items.

    Args:
        item_type: Type of items in the array

    Returns:
        Dictionary containing the array schema
    """
    return {"type": "array", "items": {"type": item_type}}


def get_agent_schema() -> Dict[str, Any]:
    """Get the JSON schema for agent YAML validation.

    Returns:
        Dictionary containing the JSON schema
    """
    return {
        "type": "object",
        "required": ["agent", "system_prompt", "tools"],
        "properties": {
            "agent": {
                "type": "object",
                "required": ["name", "uuid", "responsibilities"],
                "properties": get_agent_properties(),
            },
            "system_prompt": {"type": "string"},
            "tools": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "type"],
                    "properties": get_tool_properties(),
                },
            },
            "external_knowledge": get_array_schema(),
            "inputs": get_array_schema(),
            "outputs": get_array_schema(),
            "steps": get_array_schema(),
        },
    }


def validate_agent_yaml(file_path: str) -> bool:
    """Validate an agent YAML configuration file.

    Args:
        file_path: Path to the agent YAML file

    Returns:
        True if validation passes, False otherwise
    """
    try:
        data = load_yaml(file_path)
        schema = get_agent_schema()
        return validate_schema(data, schema)
    except Exception as e:
        error_msg = f"Error validating {file_path}: {e}"
        print(error_msg)
        return False


def validate_yaml_file(file_path: str, schema_file: str) -> bool:
    """Validate a YAML file against a schema file.

    Args:
        file_path: Path to the YAML file to validate
        schema_file: Path to the schema file

    Returns:
        True if validation passes, False otherwise
    """
    try:
        data = load_yaml(file_path)
        schema = load_schema(schema_file)
        return validate_schema(data, schema)
    except Exception as e:
        error_msg = f"Error validating {file_path}: {e}"
        print(error_msg)
        return False


def validate_yaml_files(directory: str, schema_file: str) -> List[str]:
    """Validate all YAML files in a directory against a schema.

    Args:
        directory: Directory containing YAML files to validate
        schema_file: Path to the schema file

    Returns:
        List of paths to files that failed validation
    """
    failed_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                path = os.path.join(root, file)
                if not validate_yaml_file(path, schema_file):
                    failed_files.append(path)
    return failed_files


def main() -> None:
    """Run YAML validation on specified files or directories."""
    if len(sys.argv) < 2:
        print("Usage: python validate_yaml.py <yaml_file> [schema_file]")
        sys.exit(1)

    yaml_file = sys.argv[1]
    schema_file = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(yaml_file):
        print(f"Error: File {yaml_file} does not exist")
        sys.exit(1)

    if schema_file and not os.path.exists(schema_file):
        print(f"Error: Schema file {schema_file} does not exist")
        sys.exit(1)

    if os.path.isdir(yaml_file):
        if not schema_file:
            print("Error: Schema file required when validating a directory")
            sys.exit(1)
        failed_files = validate_yaml_files(yaml_file, schema_file)
        if failed_files:
            print("\nValidation failed for the following files:")
            for file in failed_files:
                print(f"  - {file}")
            sys.exit(1)
        else:
            print("All YAML files validated successfully.")
    else:
        if validate_agent_yaml(yaml_file):
            print(f"✓ {yaml_file} is valid")
            sys.exit(0)
        else:
            print(f"✗ {yaml_file} is invalid")
            sys.exit(1)


if __name__ == "__main__":
    main()
