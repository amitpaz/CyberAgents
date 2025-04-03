#!/bin/bash
# Setup script for the Semgrep Scanner Tool

echo "Setting up Semgrep Scanner Tool..."

# Check if pip is installed
if ! command -v pip &> /dev/null; then
    echo "Error: pip is not installed. Please install Python and pip first."
    exit 1
fi

# Install Semgrep
echo "Installing Semgrep..."
pip install semgrep

# Check if Git is installed (needed for policy sync)
if ! command -v git &> /dev/null; then
    echo "Warning: Git is not installed. The policy sync feature requires Git."
    echo "Please install Git if you want to use local policies."
fi

# Create the policy directories if they don't exist
echo "Creating policy directories..."
mkdir -p "$(dirname "$0")/policies/knowledge"

# Sync policies
echo "Syncing policies (this may take a few minutes)..."
python "$(dirname "$0")/sync_policies.py"

echo "Setup complete!"
echo "You can now use the Semgrep Scanner Tool with both registry and local policies."
echo ""
echo "To sync policies for specific languages only, run:"
echo "  python tools/semgrep_scanner/sync_policies.py sync <language1> <language2> ..."
echo ""
echo "To check the current policy status, run:"
echo "  python tools/semgrep_scanner/sync_policies.py status" 