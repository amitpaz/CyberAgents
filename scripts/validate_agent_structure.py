"""Agent structure validation script."""

import os
import sys
from typing import List


def validate_agent_structure(agent_dir: str) -> List[str]:
    """Validate the structure of an agent directory."""
    errors = []
    required_files = ["agent.yaml", "README.md"]
    required_dirs = ["knowledge"]

    # Check required files
    for file in required_files:
        if not os.path.exists(os.path.join(agent_dir, file)):
            errors.append(f"Missing required file: {file}")

    # Check required directories
    for dir_name in required_dirs:
        if not os.path.isdir(os.path.join(agent_dir, dir_name)):
            errors.append(f"Missing required directory: {dir_name}")

    return errors


def main():
    """Main function to validate all agent structures."""
    agents_dir = "agents"
    if not os.path.exists(agents_dir):
        print(f"Error: {agents_dir} directory not found")
        sys.exit(1)

    all_errors = []
    for agent_dir in os.listdir(agents_dir):
        agent_path = os.path.join(agents_dir, agent_dir)
        if os.path.isdir(agent_path):
            errors = validate_agent_structure(agent_path)
            if errors:
                all_errors.append(f"\nAgent {agent_dir} has the following issues:")
                all_errors.extend([f"  - {error}" for error in errors])

    if all_errors:
        print("\n".join(all_errors))
        sys.exit(1)
    else:
        print("All agent structures are valid!")


if __name__ == "__main__":
    main()
