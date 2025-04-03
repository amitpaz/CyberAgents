# Dependency Fame and Shame

## Dependency Upgrade Blockers 🧐

These packages are preventing us from upgrading other dependencies. Shame!

| Package Blocked | Blocked By | Version Constraints | Shame Level |
|-----------------|------------|---------------------|-------------|
| `rich` | `instructor` via `crewai` | Requires `rich >=13.7.0,<14.0.0` | 🧐🧐 |
| `packaging` | `langchain-core` | Requires `packaging >=23.2,<24.0` | 🧐 |
| `tenacity` | `langchain` | Requires `tenacity >=8.1.0,<9.0.0` | 🧐 |
| `httpx` | `litellm` via `crewai` | Requires `httpx >=0.23.0,<0.28.0` | 🧐 |

## Dependency Upgrade Champions 🤩

These packages are well-maintained and allow us to use their latest versions without issues. Thank you!

| Package | Current Version | Status |
|---------|----------------|--------|
| `pytest-picked` | 0.5.1 | Successfully upgraded 🤩 |
| `pytest-asyncio` | 0.26.0 | Successfully upgraded 🤩 |
| `pytest` | 8.0.0 | Already using recent version 🤩 |
| `pytest-mock` | 3.12.0 | Already using recent version 🤩 |
| `black` | 25.1.0 | Already using recent version 🤩 |
| `flake8` | 7.0.0 | Already using recent version 🤩 |
| `mypy` | 1.8.0 | Already using recent version 🤩 |
| `pre-commit` | 4.2.0 | Already using recent version 🤩 |
| `pyyaml` | 6.0.1 | Already using recent version 🤩 |
| `jsonschema` | 4.21.1 | Already using recent version 🤩 |
| `dnspython` | 2.4.2 | Already using recent version 🤩 |
| `requests` | 2.31.0 | Already using recent version 🤩 |

## Special Mentions

The testing utilities and linting tools tend to be the most progressive in supporting modern Python and dependency versions. Infrastructure and utility libraries also perform well.

The AI/ML ecosystem packages (langchain, instructor, etc.) tend to have more complex dependency trees and strict version pinning, making upgrades more challenging.

## Maintenance Guide

This document (FAME_AND_SHAME.md) should be updated every time dependency upgrades are attempted to track:

1. **Packages that block upgrades** - When a package prevents upgrading another dependency, add it to the Blockers section with:

   - Which package is blocked
   - What's blocking it
   - The specific version constraints causing the issue
   - A shame level (🧐 for minor annoyances, 🧐🧐 for significant blockers)

1. **Successfully upgraded packages** - When a package is successfully upgraded, add or update it in the Champions section with:

   - The package name
   - The new version number
   - A status note and 🤩 emoji

1. **Packages that became unblocked** - If a package previously in the Blockers section is resolved (either by the blocking package relaxing its requirements or by upgrading the entire dependency chain), move it to the Champions section.

This document serves as both documentation and motivation to keep dependencies up to date.
