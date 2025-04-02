"""Script to validate agent directory structure and configuration files."""

import os
from typing import List


def validate_directory_structure(base_path: str) -> List[str]:
    """Validate the directory structure for an agent.

    Args:
        base_path: Path to the agent's base directory

    Returns:
        List of validation errors, empty if valid
    """
    required_dirs = ["config", "src", "tests"]
    errors = []

    for dir_name in required_dirs:
        dir_path = os.path.join(base_path, dir_name)
        if not os.path.exists(dir_path):
            errors.append(f"Missing required directory: {dir_name}")

    return errors


def validate_config_files(base_path: str) -> List[str]:
    """Validate required configuration files.

    Args:
        base_path: Path to the agent's base directory

    Returns:
        List of validation errors, empty if valid
    """
    required_files = ["config/agent.yaml", "config/schema.yaml", "README.md"]
    errors = []

    for file_path in required_files:
        full_path = os.path.join(base_path, file_path)
        if not os.path.exists(full_path):
            errors.append(f"Missing required file: {file_path}")

    return errors


def main() -> None:
    """Validate agent directory structure and configuration files."""
    base_path = os.getcwd()
    errors = []

    # Validate directory structure
    dir_errors = validate_directory_structure(base_path)
    errors.extend(dir_errors)

    # Validate configuration files
    config_errors = validate_config_files(base_path)
    errors.extend(config_errors)

    if errors:
        print("Validation failed with the following errors:")
        for error in errors:
            print(f"- {error}")
        exit(1)
    else:
        print("Validation successful!")


if __name__ == "__main__":
    main()
