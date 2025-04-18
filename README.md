# CyberAgents

CyberAgents is a framework for defining, documenting, and orchestrating AI-powered cybersecurity agents. Each agent represents a specialized function within modern security operations, from detection to governance to remediation. The goal is to enable scalable, modular, and automated cybersecurity processes using agent-based architecture.

## 📌 Project Objectives

- **Modularization** of cybersecurity roles into discrete agents
- **Declarative definitions** using structured YAML for clarity and automation (supplementary to Python config)
- **Coordination** of agents via a central manager agent and CrewAI's framework
- **Extensibility** for new agents, tools, knowledge, and domains
- **Documentation-first** to ensure clarity, auditability, and usability
- **Quality Assurance** through automated validation and testing

Each agent is defined with:

- A unique identifier and responsibilities
- A system prompt (for LLM-backed agents)
- A list of tools and external knowledge used
- Clearly defined inputs and outputs
- A sequenced list of steps and logic (handled by CrewAI orchestration)
- Associated documentation (README.md) and configuration (agent.yaml)

## 🧠 Repository Structure

```plaintext
CyberAgents/
├── agents/                     # Main directory for agent modules
│   ├── <agent_name>/           # Subdirectory for each agent
│   │   ├── __init__.py         # Makes the directory a package
│   │   ├── agent.yaml        # Agent configuration summary
│   │   ├── <agent_name>.py   # Agent class implementation
│   │   └── README.md         # Agent documentation
│   ├── base_agent.py           # Base class for agents
│   └── __init__.py             # Makes 'agents' a package
├── schemas/                    # (Optional) YAML/JSON schemas
│   └── agent_schema.yaml     # Example schema for agent.yaml
├── scripts/                    # Utility scripts (non-core)
│   └── ...
├── tests/                      # Main test directory
│   ├── __init__.py
│   ├── agents/               # Agent-specific tests
│   │   └── test_<agent_name>.py
│   ├── tools/                # Tool-specific tests
│   │   └── test_<tool_name>.py
│   ├── crew/                 # Crew and integration tests
│   │   └── test_crew_*.py
│   ├── main/                 # Tests for main.py and CLI
│   │   └── test_main.py
│   │   └── test_security.py
│   ├── utils/                # Tests for utility functions
│   │   └── test_*.py
│   └── conftest.py           # Pytest configuration and fixtures
├── tools/                      # Tools used by agents
│   ├── __init__.py           # Makes 'tools' a package
│   ├── <tool_name>.py        # Tool implementation
│   └── validation_utils.py   # Shared input validation functions for tools
│   └── ...
├── utils/
│   ├── __init__.py           # Makes 'utils' a package
│   ├── llm_utils.py          # LLM configuration utilities
│   └── ...                   # Other shared utilities
├── .github/
│   ├── workflows/
│   │   ├── pr-validation.yml # CI workflow for Pull Requests
│   │   └── manual-release.yml # Workflow for manual GitHub releases
│   └── scripts/
│       └── install_ollama.sh # Helper script for CI Ollama setup
├── .cursor-rules/            # Rules for AI code generation (ignored by git)
├── .env.example              # Example environment variables file
├── .gitignore
├── main.py                   # Main script for running analysis via CLI
├── poetry.lock
├── pyproject.toml            # Project metadata and dependencies (Poetry)
├── setup.sh                  # Automated setup script for macOS/Linux
└── README.md
```

## 🧩 Agent Status Overview

| Agent Name                | Description                                                    | Documentation Status | Version | Last Updated |
| ------------------------- | -------------------------------------------------------------- | -------------------- | ------- | ------------ |
| Security Manager Agent    | Orchestrates analysis, delegates tasks, synthesizes reports    | 🧪 In Progress       | 0.1.0   | Apr 2024     |
| Domain WHOIS Agent        | Retrieves and parses WHOIS registration data                   | 🧪 In Progress       | 0.1.0   | Apr 2024     |
| DNS Analyzer Agent        | Retrieves and analyzes various DNS records                     | 🧪 In Progress       | 0.1.0   | Apr 2024     |
| Threat Intel Agent        | Assesses domain security threats using VirusTotal              | 🧪 In Progress       | 0.1.0   | Apr 2024     |
| Exposure Analyst Agent    | Analyzes external exposure/attack surface (subdomains, Shodan, ASN, Nmap) | 🧪 In Progress | 0.1.0   | Apr 2024     |
| Email Security Agent      | Validates SPF and DMARC DNS records                            | 🧪 In Progress       | 0.1.0   | Apr 2024     |
| Cloud Security            | Validate & Enforces cloud security configs                     | 🧪 In Progress       | 0.1.0   | Apr 2024     |
| *Defect Review Agent*     | *(Placeholder) Reviews code/system defects for security*      | ❌ Draft             | -       | -            |
| *SOC Analyst*             | *(Placeholder) Simulates L1-2 SOC analyst duties*             | ❌ Draft             | -       | -            |
| *Incident Responder*      | *(Placeholder) Performs containment, eradication, recovery*     | ❌ Draft             | -       | -            |
| *Red Team Agent*          | *(Placeholder) Simulates offensive attacker behavior*          | ❌ Draft             | -       | -            |
| *Governance Agent*        | *(Placeholder) Evaluates adherence to security governance*     | ❌ Draft             | -       | -            |
| *Compliance Agent*        | *(Placeholder) Maps posture against compliance frameworks*     | ❌ Draft             | -       | -            |
| *Evidence Collection*     | *(Placeholder) Collects forensic data*                         | ❌ Draft             | -       | -            |
| *Security Operations*     | *(Placeholder) Oversees operational security controls*         | ❌ Draft             | -       | -            |
| *Change Management*       | *(Placeholder) Assesses security impacts of changes*           | ❌ Draft             | -       | -            |
| *Network Security*        | *(Placeholder) Monitors/enforces network rules*                | ❌ Draft             | -       | -            |
| *Endpoint Security*       | *(Placeholder) Manages EDR logic/response*                     | ❌ Draft             | -       | -            |
| *Security Reporting*      | *(Placeholder) Generates security KPIs/reports*                | ❌ Draft             | -       | -            |

> **Legend**:
>
> - `🧪 In Progress`: Basic implementation, configuration, README, and tests exist.
> - `❌ Draft`: Placeholder exists, not implemented.
> - `✅ Complete`: Full definition, documentation, and robust tests available.

## 🚀 Getting Started

### Automated Setup (Recommended)

For macOS and Linux users, the easiest way to get started is using the setup script. It checks for prerequisites (like Python 3.11+, Homebrew on macOS, Poetry, Ollama) and installs them if missing (except for Python and Homebrew, which must be installed manually first). It also installs project dependencies and sets up the default local Ollama model.

1. **Clone the repository:**

   ```bash
   git clone https://github.com/NaorPenso/CyberAgents.git
   cd CyberAgents
   ```

1. **Run the setup script:**

   ```bash
   bash setup.sh
   # Or: ./setup.sh
   ```

   - Follow any prompts from the script (e.g., for `sudo` password if installing system packages).
   - If the script fails due to missing prerequisites like Python or Homebrew, install them manually and re-run the script.

1. **Configure Environment Variables:**

   - The script copies `.env.example` to `.env` if it doesn't exist.
   - **Crucially, edit the `.env` file** and add your necessary API keys:
     ```dotenv
     OPENAI_API_KEY="sk-proj-..." # Required if NOT using local LLM
     VIRUSTOTAL_API_KEY="your_vt_api_key" # Required for ThreatIntelAgent
     SHODAN_API_KEY="your_shodan_api_key" # Required for Shodan tool in ExposureAnalystAgent

     # --- Optional / Testing ---
     # Set to true to use local Ollama instead of OpenAI for main.py runs
     # USE_LOCAL_LLM="false"
     # OLLAMA_BASE_URL="http://localhost:11434/v1" # Default if USE_LOCAL_LLM=true
     # OLLAMA_MODEL="phi:latest" # Default if USE_LOCAL_LLM=true

     # --- Optional Telemetry ---
     # OTEL_EXPORTER_OTLP_ENDPOINT="your_otlp_endpoint"
     ```

### Manual Installation

1. **Clone:** `git clone https://github.com/NaorPenso/CyberAgents.git && cd CyberAgents`
1. **Prerequisites:**
   - Ensure Python 3.11+ is installed.
   - (macOS) Ensure Homebrew is installed: `brew --version`.
   - Install Poetry: See [Poetry installation guide](https://python-poetry.org/docs/#installation).
   - (Optional, for local LLM testing) Install Ollama: See [Ollama website](https://ollama.com/).
1. **Install dependencies:** `poetry install --extras test`
1. **Configure Environment:** Copy `.env.example` to `.env` and add your API keys (see step 3 above).
1. **(Optional, for local LLM testing)** Pull a model: `ollama pull phi:latest`
1. **(Optional but recommended)** Install pre-commit hooks: `poetry run pre-commit install`

## ▶️ Usage

Run analyses from the command line using `main.py`, providing your request as a string argument. The Security Manager agent interprets the prompt and delegates tasks to relevant specialists.

```bash
# Activate the virtual environment
poetry shell

# Run analysis (using default Rich output)
python main.py "Analyze domain example.com"

# Run with verbose agent output
python main.py "Get WHOIS for google.com" --verbose

# Get JSON output (printed to stdout)
python main.py "Check DNS for mitre.org" --output=json

# Save report to a file (YAML)
python main.py "Scan subdomains for tesla.com" --output=yaml

# Save report to a file (CSV - basic format)
python main.py "Find Shodan hosts for example.com" --output=csv

# Use local Ollama model (if server is running and USE_LOCAL_LLM=true in .env)
python main.py "Analyze domain internal.local"
```

Output Formats (`--output` flag):

- `rich`: Formatted output in the terminal (Default).
- `json`: Raw JSON output printed to standard output.
- `yaml`, `csv`, `html`: Saves the main analysis report content to `analysis_report.<format>`. (Note: CSV/YAML conversion from the report string is basic).

## 🧪 Testing and Validation

The project includes several validation mechanisms:

1. **YAML Schema Validation (If used):**

   - Validates agent configurations (`agents/**/agent.yaml`) against `schemas/agent_schema.yaml` (if schema exists).
   - Ensures proper structure and required fields via custom scripts (if developed, e.g., `scripts/validate_yaml.py`).

1. **Unit & Integration Tests:**

   - Tests are located under the main `tests/` directory, categorized into subdirectories (`agents/`, `tools/`, `crew/`, `main/`, `utils/`).
   - Run all tests: `poetry run pytest -vv tests/`
   - Run tests for a specific category: `poetry run pytest -vv tests/tools/`

1. **Pre-commit Hooks:**

   - Code formatting (Black)
   - Linting (Flake8)
   - Type checking (MyPy)
   - YAML linting (yamllint)

1. **GitHub Actions (`.github/workflows/pr-validation.yml`):**

   - Runs on every pull request to `main`.
   - Installs dependencies using Poetry.
   - Runs tests on changed files using `pytest-picked`, split by category (`tests`, `agents`, `tools`). Security tests (`tests/main/test_security.py`) run separately.
   - Runs Semgrep security scan.
   - Runs Dependency Review scan to check for vulnerable dependencies (fails on High/Critical).
   - Allows manual triggering to choose between local Ollama (default for tests) or remote OpenAI.

## 📦 Releases

- Releases are created manually via GitHub Releases.
- Use the "Manual GitHub Release" workflow in the Actions tab to create versioned releases and tags.
- Versioning follows Semantic Versioning (SemVer).

## 📬 Contributing

*(Preserve original Contributing section here if it existed)*
See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for guidelines on:

- Submitting issues
- Creating pull requests
- Following semantic commit conventions
- Writing documentation
- Adding new agents or workflows

## 📖 License

*(Preserve original License section here if it existed)*
This project is licensed under the MIT License. See `LICENSE` for details.
