# CyberAgents

A Python project demonstrating a modular, agent-based system for cyber intelligence tasks, initially focused on domain analysis.

## Overview

This project utilizes the CrewAI framework to build a team of specialized AI agents managed by a central Security Manager agent. The system dynamically discovers and loads available agents, allowing for easy extension.

Users interact via a command-line interface, providing a natural language prompt (e.g., "Analyze domain example.com") which the Security Manager interprets and delegates to the appropriate specialist agents.

## Features

*   **Modular Agent Architecture:** Each agent has a specific role and resides in its own module (`agents/<agent_name>/`).
*   **Dynamic Agent Discovery:** The system automatically finds and loads available agents at runtime.
*   **Manager-Led Orchestration:** A `SecurityManagerAgent` coordinates task delegation and result synthesis.
*   **Specialized Agents:** Includes agents for specific domain intelligence tasks.
*   **CLI Interface:** Run analyses via `python main.py "<prompt>"`.
*   **Configuration:** Agents and tools can be partially configured via YAML files (though primary configuration is currently in Python).
*   **Extensible:** Add new agents by creating a new module in the `agents/` directory following the established pattern.
*   **Telemetry:** Basic OpenTelemetry integration for tracing and metrics (requires OTLP endpoint configuration).

## Current Agents (v0.1.0 - Alpha)

The following agents are currently implemented. All are considered **Alpha** status:

*   **Security Manager Agent:** Orchestrates the crew, interprets user prompts, delegates tasks, and synthesizes the final report.
*   **Domain WHOIS Agent:** Retrieves and parses WHOIS registration data for domains.
*   **DNS Analyzer Agent:** Retrieves and analyzes various DNS records (A, MX, NS, TXT, AAAA, DNSSEC) for domains.
*   **Threat Intel Agent:** Assesses domain security threats using VirusTotal.
*   **Email Security Agent:** Validates SPF and DMARC DNS records for domains.

## Setup & Installation

This project uses Poetry for dependency management.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/NaorPenso/CyberAgents.git
    cd CyberAgents
    ```
2.  **Install dependencies:**
    ```bash
    poetry install
    ```
3.  **Environment Variables:**
    *   Create a `.env` file in the project root.
    *   Add necessary API keys:
        ```dotenv
        OPENAI_API_KEY="your_openai_api_key"
        # OPENAI_API_BASE="your_openai_api_base" # Optional: If using a custom base URL
        # OPENAI_MODEL_NAME="gpt-4" # Optional: Defaults to o3-mini
        VIRUSTOTAL_API_KEY="your_virustotal_api_key" # Required for ThreatIntelAgent
        # OTEL_EXPORTER_OTLP_ENDPOINT="your_otlp_endpoint" # Optional: For telemetry export
        ```

## Usage

Run analyses from the command line using `main.py`, providing your request as a string argument:

```bash
poetry run python main.py "Analyze domain example.com focusing on DNS and WHOIS."
```

**Examples:**

*   Full analysis: `poetry run python main.py "Perform a full security analysis on google.com"`
*   Specific checks: `poetry run python main.py "Check the SPF and DMARC records for example.org"`
*   Multiple checks: `poetry run python main.py "Get WHOIS and Threat Intel for badsite.xyz"`

The Security Manager agent will interpret the prompt and delegate tasks to the relevant specialist agents. The final synthesized report will be logged to the console as JSON.

## Testing

Tests are located in the `tests/` directory and within each agent's subdirectory (`agents/<agent_name>/test_*.py`).

*   **Run all tests:**
    ```bash
    poetry run pytest -v
    ```
*   **Run tests for changed files (requires test extra):**
    ```bash
    # Install extras if needed: poetry install --extras test
    poetry run pytest --picked --parent-branch origin/main -v 
    ```

CI checks are run via the `.github/workflows/pr-validation.yml` workflow, including `pytest-picked` and Semgrep scans.

## Contributing

Contributions are welcome! Please follow standard PR procedures.

## License

(Specify your license here, e.g., MIT License)
