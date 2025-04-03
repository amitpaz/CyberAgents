#!/bin/bash
# Script to install dependencies and run all tests

# Exit on error
set -e

echo "==============================================="
echo "  Running CyberAgents Tests with Poetry"
echo "==============================================="

# Install dependencies
echo "Installing dependencies with Poetry..."
poetry install --extras test

# Ensure crewai is installed (identified as missing)
echo "Ensuring crewai is installed..."
poetry add crewai --group dev

# Run the tests
echo "Running all tests..."
poetry run pytest -v

echo "Tests completed!"
