#!/usr/bin/env python3
"""
Validate that FAME_AND_SHAME.md follows the template structure.
"""

import re
import sys
from pathlib import Path


def validate_fame_shame_document():
    """
    Validate that FAME_AND_SHAME.md follows the template structure.
    Returns a tuple of (is_valid, errors).
    """
    repo_root = Path(__file__).parent.parent.parent
    fame_shame_path = repo_root / "FAME_AND_SHAME.md"
    template_path = repo_root / ".github" / "TEMPLATES" / "FAME_AND_SHAME_TEMPLATE.md"

    if not fame_shame_path.exists():
        return False, ["FAME_AND_SHAME.md file not found"]

    if not template_path.exists():
        return False, [
            "Template file not found at .github/TEMPLATES/FAME_AND_SHAME_TEMPLATE.md"
        ]

    with open(fame_shame_path, "r") as f:
        content = f.read()

    errors = []

    # Check for required headers
    required_headers = [
        "# Dependency Fame and Shame",
        "## Dependency Upgrade Blockers 🧐",
        "## Dependency Upgrade Champions 🤩",
        "## Special Mentions",
        "## Maintenance Guide",
    ]
    for header in required_headers:
        if header not in content:
            errors.append(f"Missing required header: {header}")

    # Check table headers
    blocker_table_header = "| Package | Blocked By | Version Constraint | Shame Level |"
    if blocker_table_header not in content:
        errors.append(
            f"Blockers table header doesn't match template: {blocker_table_header}"
        )

    champion_table_header = "| Package | Current Version | Status |"
    if champion_table_header not in content:
        errors.append(
            f"Champions table header doesn't match template: {champion_table_header}"
        )

    # Use simpler approach: find all table rows with package names
    package_pattern = r"\|\s*(`[^`]+`)\s*\|"
    packages = re.findall(package_pattern, content)
    if not packages:
        errors.append("No properly formatted package names found in tables")

    # Check version formatting in champion table
    version_pattern = r"\|\s*`[^`]+`\s*\|\s*(`[^`]+`)\s*\|"
    versions = re.findall(version_pattern, content)
    if not versions:
        errors.append("No properly formatted version numbers found in champion table")

    # Check for shame level format (just basic validation)
    shame_levels = re.findall(r"\|\s*(🧐+)\s*\|", content)
    for level in shame_levels:
        if level not in ["🧐", "🧐🧐"]:
            errors.append(f"Invalid shame level format: {level}")

    # Check status entries (basic validation)
    status_pattern = (
        r"\|\s*(Successfully upgraded 🤩|Already using recent version 🤩)\s*\|"
    )
    status_entries = re.findall(status_pattern, content)
    if not status_entries:
        errors.append("No valid status entries found in champion table")

    # Check numbered list in maintenance guide
    if "1. **Packages that block upgrades**" not in content:
        errors.append("Missing numbered item 1 in maintenance guide")
    if "2. **Successfully upgraded packages**" not in content:
        errors.append("Missing numbered item 2 in maintenance guide")
    if "3. **Packages that became unblocked**" not in content:
        errors.append("Missing numbered item 3 in maintenance guide")

    # Verify checklist is present
    if "### Template Validation Checklist" not in content:
        errors.append("Missing validation checklist section")

    # Verify checklist items
    checklist_items = [
        "- [ ] All table headers match the template exactly",
        "- [ ] Package names are enclosed in backticks",
        "- [ ] Version numbers follow semantic versioning format",
        "- [ ] Status entries end with appropriate emoji",
        "- [ ] Shame levels use only the defined emoji set",
        "- [ ] Numbered list in maintenance guide uses correct sequential numbering",
    ]

    for item in checklist_items:
        if item not in content:
            errors.append(f"Missing checklist item: {item}")

    return len(errors) == 0, errors


if __name__ == "__main__":
    is_valid, errors = validate_fame_shame_document()

    if not is_valid:
        print("❌ FAME_AND_SHAME.md validation failed!")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)
    else:
        print("✅ FAME_AND_SHAME.md validation successful!")
        sys.exit(0)
