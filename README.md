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
│   │   ├── README.md         # Agent documentation
│   │   └── test_<agent_name>.py # Agent-specific tests
│   └── __init__.py             # Makes 'agents' a package
├── schemas/
│   ├── agent_schema.yaml     # YAML schema for agent configuration files
│   └── tool_schema.yaml      # YAML schema for tool configuration files (if used)
├── scripts/
│   ├── validate_yaml.py      # YAML validation script
│   └── ...                   # Other utility scripts
├── tests/
│   ├── __init__.py
│   ├── test_agent_suite.py   # Runner/placeholder for agent tests
│   ├── test_crew_integration.py # Integration tests for the crew
│   ├── test_security.py      # Security-focused tests
│   └── ...                   # Other general tests (API, etc.)
├── tools/
│   ├── __init__.py           # Makes 'tools' a package
│   ├── <tool_name>.py        # Tool implementation (e.g., whois_tool.py)
│   └── ...
├── utils/
│   ├── __init__.py           # Makes 'utils' a package
│   ├── llm_utils.py          # LLM configuration utilities
│   └── ...                   # Other shared utilities
├── .github/
│   └── workflows/
│       └── pr-validation.yml # CI workflow for Pull Requests
├── .cursor-rules/            # Rules for AI code generation (ignored by git)
├── .env.example              # Example environment variables file
├── .gitignore
├── main.py                   # Main script for running analysis via CLI
├── poetry.lock
├── pyproject.toml            # Project metadata and dependencies (Poetry)
└── README.md
```

## 🧩 Agent Status Overview

| Agent Name                | Description                                                    | Documentation Status | Version |
| ------------------------- | -------------------------------------------------------------- | -------------------- | ------- |
| Security Manager Agent    | Orchestrates analysis, delegates tasks, synthesizes reports    | 🧪 In Progress       | 0.1.0   |
| Domain WHOIS Agent        | Retrieves and parses WHOIS registration data                   | 🧪 In Progress       | 0.1.0   |
| DNS Analyzer Agent        | Retrieves and analyzes various DNS records                     | 🧪 In Progress       | 0.1.0   |
| Threat Intel Agent        | Assesses domain security threats using VirusTotal              | 🧪 In Progress       | 0.1.0   |
| Email Security Agent      | Validates SPF and DMARC DNS records                            | 🧪 In Progress       | 0.1.0   |
| *Defect Review Agent*     | *(Placeholder) Reviews code/system defects for security*      | ❌ Draft             | -       |
| *Exposure Analyst*        | *(Placeholder) Analyzes external exposure/attack surface*      | ❌ Draft             | -       |
| *SOC Analyst*             | *(Placeholder) Simulates L1-2 SOC analyst duties*             | ❌ Draft             | -       |
| *Incident Responder*      | *(Placeholder) Performs containment, eradication, recovery*     | ❌ Draft             | -       |
| *Red Team Agent*          | *(Placeholder) Simulates offensive attacker behavior*          | ❌ Draft             | -       |
| *Governance Agent*        | *(Placeholder) Evaluates adherence to security governance*     | ❌ Draft             | -       |
| *Compliance Agent*        | *(Placeholder) Maps posture against compliance frameworks*     | ❌ Draft             | -       |
| *Evidence Collection*     | *(Placeholder) Collects forensic data*                         | ❌ Draft             | -       |
| *Security Operations*     | *(Placeholder) Oversees operational security controls*         | ❌ Draft             | -       |
| *Change Management*       | *(Placeholder) Assesses security impacts of changes*           | ❌ Draft             | -       |
| *Network Security*        | *(Placeholder) Monitors/enforces network rules*                | ❌ Draft             | -       |
| *Endpoint Security*       | *(Placeholder) Manages EDR logic/response*                     | ❌ Draft             | -       |
| *Cloud Security*          | *(Placeholder) Enforces cloud security configs*                | ❌ Draft             | -       |
| *Security Reporting*      | *(Placeholder) Generates security KPIs/reports*                | ❌ Draft             | -       |

> **Legend**:
>
> - `🧪 In Progress`: Basic implementation, configuration, README, and tests exist.
> - `❌ Draft`: Placeholder exists, not implemented.
> - `✅ Complete`: Full definition, documentation, and robust tests available.

## 🚀 Getting Started

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/NaorPenso/CyberAgents.git
    cd CyberAgents
    ```

2.  **Install Poetry** (if you don't have it): See [Poetry installation guide](https://python-poetry.org/docs/#installation).

3.  **Install dependencies:**

    ```bash
    poetry install
    ```

4.  **Configure Environment Variables:**
    *   Copy the example environment file: `cp .env.example .env`
    *   Edit the `.env` file and add your API keys:
        ```dotenv
        OPENAI_API_KEY="your_openai_api_key"
        # OPENAI_API_BASE="your_openai_api_base" # Optional
        # OPENAI_MODEL_NAME="gpt-4" # Optional, defaults to o3-mini
        VIRUSTOTAL_API_KEY="your_virustotal_api_key" # Required for ThreatIntelAgent
        # OTEL_EXPORTER_OTLP_ENDPOINT="your_otlp_endpoint" # Optional
        ```

5.  **Install pre-commit hooks (Optional but recommended):**

    ```bash
    poetry run pre-commit install
    ```

## ▶️ Usage

Run analyses from the command line using `main.py`, providing your request as a string argument. The Security Manager agent interprets the prompt and delegates tasks to relevant specialists.

```bash
poetry run python main.py "Your analysis request here"
```

**Examples:**

*   `poetry run python main.py "Perform a full security analysis on google.com"`
*   `poetry run python main.py "Check the SPF and DMARC records for example.org"`
*   `poetry run python main.py "Get WHOIS and Threat Intel for badsite.xyz"`

The final synthesized report will be logged to the console as JSON.

## 🧪 Testing and Validation

The project includes several validation mechanisms:

1.  **YAML Schema Validation:**
    *   Validates agent configurations (`agents/**/agent.yaml`) against `schemas/agent_schema.yaml`.
    *   (If used) Validates tool configurations against `schemas/tool_schema.yaml`.
    *   Ensures proper structure and required fields via `scripts/validate_yaml.py`.

2.  **Unit & Integration Tests:**
    *   Agent-specific tests are located in `agents/<agent_name>/test_*.py`.
    *   Integration tests for the crew are in `tests/test_crew_integration.py`.
    *   Run all tests: `poetry run pytest -v`
    *   Run tests for changed files (PRs): `poetry run pytest --picked --parent-branch origin/main -v` (requires `poetry install --extras test`)

3.  **Pre-commit Hooks:**
    *   Code formatting (Black)
    *   Linting (Flake8)
    *   Type checking (MyPy)
    *   YAML validation (via `scripts/validate_yaml.py` if configured in `.pre-commit-config.yaml`)

4.  **GitHub Actions:**
    *   Runs on every pull request to `main` via `.github/workflows/pr-validation.yml`.
    *   Installs dependencies using Poetry.
    *   Runs tests on changed files using `pytest-picked`.
    *   Runs Semgrep security scan.

## 📦 Releases

*(Preserve original Releases section here if it existed)*
- Releases will be managed via GitHub Releases.
- Versioning will follow Semantic Versioning (SemVer).

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
