#!/usr/bin/env python3
import sys
import yaml
import jsonschema
from pathlib import Path


def load_yaml(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f)


def load_schema(schema_path):
    with open(schema_path, "r") as f:
        return yaml.safe_load(f)


def validate_yaml(data, schema):
    try:
        jsonschema.validate(instance=data, schema=schema)
        return True, None
    except jsonschema.exceptions.ValidationError as e:
        return False, str(e)


def main():
    if len(sys.argv) < 2:
        print("Usage: validate_yaml.py <yaml_file> [schema_file]")
        sys.exit(1)

    yaml_file = sys.argv[1]
    schema_file = sys.argv[2] if len(sys.argv) > 2 else "schemas/agent_schema.yaml"

    if not Path(yaml_file).exists():
        print(f"Error: File {yaml_file} does not exist")
        sys.exit(1)

    if not Path(schema_file).exists():
        print(f"Error: Schema file {schema_file} does not exist")
        sys.exit(1)

    try:
        data = load_yaml(yaml_file)
        schema = load_schema(schema_file)
        is_valid, error = validate_yaml(data, schema)

        if is_valid:
            print(f"✓ {yaml_file} is valid")
            sys.exit(0)
        else:
            print(f"✗ {yaml_file} is invalid:")
            print(error)
            sys.exit(1)

    except Exception as e:
        print(f"Error processing {yaml_file}: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
