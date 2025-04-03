# Dependency Fame and Shame

## Dependency Upgrade Blockers 🧐

These packages are preventing us from upgrading other dependencies. Shame!

| Package | Blocked By | Version Constraint | Shame Level |
|---------|------------|-------------------|-------------|
| `rich` | `instructor` via `crewai` | `>=13.7.0,<14.0.0` | 🧐🧐 |
| `packaging` | `langchain-core` | `>=23.2,<24.0` | 🧐 |
| `tenacity` | `langchain` | `>=8.1.0,<9.0.0` | 🧐 |
| `httpx` | `litellm` via `crewai` | `>=0.23.0,<0.28.0` | 🧐 |
| `importlib-metadata` | `opentelemetry-api` | `>=6.0,<7.0` | 🧐 |
| `pydantic-core` | `crewai` via `instructor` | Complex version chain | 🧐🧐 |
| `numpy` | `langchain` | `>=1,<2` | 🧐 |

## Dependency Upgrade Champions 🤩

These packages are well-maintained and allow us to use their latest versions without issues. Thank you!

| Package | Current Version | Status |
|---------|----------------|--------|
| `fastapi` | `0.115.12` | Successfully upgraded 🤩 |
| `starlette` | `0.46.1` | Successfully upgraded 🤩 |
| `uvicorn` | `0.34.0` | Successfully upgraded 🤩 |
| `typer` | `0.15.2` | Successfully upgraded 🤩 |
| `vt-py` | `0.20.0` | Successfully upgraded 🤩 |
| `python-whois` | `0.9.5` | Successfully upgraded 🤩 |
| `pytest-picked` | `0.5.1` | Successfully upgraded 🤩 |
| `pytest-asyncio` | `0.26.0` | Successfully upgraded 🤩 |
| `opentelemetry-api` | `1.31.1` | Successfully upgraded 🤩 |
| `opentelemetry-sdk` | `1.31.1` | Successfully upgraded 🤩 |
| `opentelemetry-instrumentation` | `0.52b1` | Successfully upgraded 🤩 |
| `protobuf` | `5.29.4` | Successfully upgraded 🤩 |
| `pytest` | `8.0.0` | Already using recent version 🤩 |
| `pytest-mock` | `3.12.0` | Already using recent version 🤩 |
| `black` | `25.1.0` | Already using recent version 🤩 |
| `flake8` | `7.0.0` | Already using recent version 🤩 |
| `mypy` | `1.8.0` | Already using recent version 🤩 |
| `pre-commit` | `4.2.0` | Already using recent version 🤩 |
| `pyyaml` | `6.0.1` | Already using recent version 🤩 |
| `jsonschema` | `4.21.1` | Already using recent version 🤩 |
| `dnspython` | `2.4.2` | Already using recent version 🤩 |
| `requests` | `2.31.0` | Already using recent version 🤩 |

## Special Mentions

The testing utilities and linting tools tend to be the most progressive in supporting modern Python and dependency versions. Infrastructure and utility libraries also perform well.

The AI/ML ecosystem packages (langchain, instructor, etc.) tend to have more complex dependency trees and strict version pinning, making upgrades more challenging.

## Maintenance Guide

This document (FAME_AND_SHAME.md) should be updated every time dependency upgrades are attempted to track:

1. **Packages that block upgrades** - When a package prevents upgrading another dependency, add it to the Blockers section with:

   - Package name (the one being blocked)
   - Blocking package name (what's blocking it)
   - Specific version constraints causing the issue
   - Shame level (🧐 for minor annoyances, 🧐🧐 for significant blockers)

2. **Successfully upgraded packages** - When a package is successfully upgraded, add or update it in the Champions section with:

   - Package name
   - New version number
   - Status (either "Successfully upgraded 🤩" or "Already using recent version 🤩")

3. **Packages that became unblocked** - If a package previously in the Blockers section is resolved (either by the blocking package relaxing its requirements or by upgrading the entire dependency chain), move it to the Champions section.

4. **Template validation** - After making any changes, run the validation script to ensure the document follows the standardized format:
   ```bash
   python .github/scripts/validate_fame_shame.py
   ```

### Template Validation Checklist

Before committing changes to FAME_AND_SHAME.md, verify:

- [ ] All table headers match the template exactly
- [ ] Package names are enclosed in backticks
- [ ] Version numbers follow semantic versioning format
- [ ] Status entries end with appropriate emoji
- [ ] Shame levels use only the defined emoji set (🧐 or 🧐🧐)
- [ ] Numbered list in maintenance guide uses correct sequential numbering

This document serves as both documentation and motivation to keep dependencies up to date.
