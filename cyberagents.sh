#!/bin/bash

# Script to run Domain Intelligence Crew analysis using Poetry
# Usage: ./cyberagents.sh ["Analyze domain example.com"] [output_format] [verbose]

# ASCII Art Banner
echo ""
echo " ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗  ██████╗ ███████╗███╗   ██╗████████╗███████╗"
echo "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██╔════╝"
echo "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ███████╗"
echo "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║"
echo "╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ███████║"
echo " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝"
echo ""

# Default values
DEFAULT_OUTPUT="rich"

# Parse prompt - if not provided, ask the user interactively
if [ -z "$1" ]; then
    echo "What would you like the CyberAgents to analyze? (e.g., 'Analyze domain example.com')"
    read -p "> " PROMPT
    # Check if the input is empty
    if [ -z "$PROMPT" ]; then
        echo "No input provided. Exiting."
        exit 1
    fi
else
    PROMPT="$1"
fi

# Output format
OUTPUT="${2:-$DEFAULT_OUTPUT}"  # Use second argument as output format or default if not provided
VERBOSE_FLAG=""

# Check if verbose flag is set
if [ "$3" = "verbose" ] || [ "$3" = "--verbose" ] || [ "$3" = "-v" ]; then
    VERBOSE_FLAG="--verbose"
fi

# Display what we're about to do
echo "Running Domain Intelligence Crew with:"
echo "Prompt: $PROMPT"
echo "Output format: $OUTPUT"
if [ -n "$VERBOSE_FLAG" ]; then
    echo "Verbose mode: enabled"
else
    echo "Verbose mode: disabled"
fi
echo ""

# Run the analysis using Poetry
poetry run python main.py "$PROMPT" --output "$OUTPUT" $VERBOSE_FLAG

# Make script exit with the same code as the python command
exit $?
