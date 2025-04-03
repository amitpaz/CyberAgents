#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

echo "--- Installing Ollama --- "
# Download the Ollama installation script and execute it
# Sudo might be required depending on the runner environment
curl -fsSL https://ollama.com/install.sh | sh

# Verify installation (optional)
ollama --version

echo "--- Pulling Ollama model (phi:latest) --- "
# Pull the model needed for tests
# Run in background in case it takes time, but we don't strictly need to wait here
ollama pull phi:latest &

# Attempt to start the Ollama server in the background
# Check if it's already running (e.g., from systemd service)
p=$(pgrep ollama)
if [ -z "$p" ]; then
  echo "--- Starting Ollama server in background --- "
  # Use nohup to keep it running even if the script exits
  # Redirect stdout/stderr to a log file for debugging
  nohup ollama serve > ollama_server.log 2>&1 &
  # Give it a moment to start up
  sleep 5
  # Check if it started successfully
  p=$(pgrep ollama)
  if [ -z "$p" ]; then
    echo "ERROR: Ollama server failed to start. Check ollama_server.log"
    cat ollama_server.log
    exit 1
  else
    echo "Ollama server started with PID $p."
  fi
else
  echo "Ollama server appears to be already running (PID $p)."
fi

echo "--- Ollama setup complete --- "
