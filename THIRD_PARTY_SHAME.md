# Third-Party Dependency Hall of Shame and Fame

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
