#!/bin/bash
# Script to run Semgrep security scans locally
# Usage:
#   ./scripts/run_semgrep.sh [options] [directory]
#
# Options:
#   --python: Run Python-specific security rules
#   --bash: Run Bash-specific security rules
#   --all: Run all rules (default)
#   --help: Show this help message
#
# If directory is not specified, scans the entire repository

set -e

# Ensure script is run from the project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

# Function to show help
show_help() {
    echo "Usage: ./scripts/run_semgrep.sh [options] [directory]"
    echo ""
    echo "Options:"
    echo "  --python: Run Python-specific security rules"
    echo "  --bash: Run Bash-specific security rules"
    echo "  --all: Run all rules (default)"
    echo "  --help: Show this help message"
    echo ""
    echo "If directory is not specified, scans the entire repository"
}

# Check if semgrep is installed
if ! command -v semgrep &> /dev/null; then
    echo "Semgrep is not installed. Installing with pip..."
    pip install semgrep
fi

# Default settings
SCAN_TYPE="all"
TARGET_DIR="."
ADDITIONAL_ARGS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --python)
            SCAN_TYPE="python"
            shift
            ;;
        --bash)
            SCAN_TYPE="bash"
            shift
            ;;
        --all)
            SCAN_TYPE="all"
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        --*)
            # Pass through any other options to semgrep
            ADDITIONAL_ARGS="$ADDITIONAL_ARGS $1"
            shift
            ;;
        *)
            TARGET_DIR="$1"
            shift
            ;;
    esac
done

echo "Running Semgrep security scan on: $TARGET_DIR"

# Configure the scan based on type
case "$SCAN_TYPE" in
    python)
        echo "Running Python-specific security scan"
        semgrep --config=p/python \
                --include="**/*.py" \
                --severity=WARNING \
                --verbose \
                $ADDITIONAL_ARGS \
                "$TARGET_DIR"
        ;;
    bash)
        echo "Running Bash-specific security scan"
        semgrep --config=r/bash \
                --include="**/*.sh" \
                --include="scripts/*" \
                --severity=WARNING \
                --verbose \
                $ADDITIONAL_ARGS \
                "$TARGET_DIR"
        ;;
    all)
        echo "Running comprehensive security scan with multiple rule packs"
        semgrep --config=p/python \
                --config=r/bash \
                --config=p/owasp-top-ten \
                --config=p/security-audit \
                --severity=WARNING \
                --verbose \
                $ADDITIONAL_ARGS \
                "$TARGET_DIR"
        ;;
esac

echo "Semgrep scan complete."
