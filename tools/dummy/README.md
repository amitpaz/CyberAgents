# Dummy Tool Template

**IMPORTANT: This is a dummy template for demonstrating the standard structure of tool documentation. When creating a real tool, replace all placeholder content with your actual tool implementation details.**

## Overview

This is a template for creating new tools in the CyberAgents project. Use this as a starting point by copying the directory structure and files, then customizing them for your specific tool.

## Features

- Example feature one
- Example feature two
- Example feature three

## Usage

### Basic Usage

```python
from tools.dummy.dummy import DummyTool

# Initialize the tool
dummy_tool = DummyTool()

# Run with standard query
result = dummy_tool.run("standard query")
print(result)

# Run with specific parameter format
result = dummy_tool.run("example:test-parameter")
print(result)
```

### Input Formats

The tool supports these input formats:

1. **Example specific format**:
   ```python
   result = dummy_tool.run("example:parameter")
   ```

2. **Standard query format**:
   ```python
   result = dummy_tool.run("your standard query here")
   ```

## Configuration

The tool can be configured with:

- `API_KEY` environment variable - API key for external service (if needed)
- `BASE_URL` environment variable - Custom API URL (default: https://api.example.com)

Or when initializing the tool:

```python
dummy_tool = DummyTool(
    api_key="your_api_key",
    base_url="https://custom-api-endpoint.com"
)
```

## Testing

To test the tool, run:

```bash
poetry run python -m unittest tools.dummy.test_dummy
```

## Dependencies

- requests
- langchain.tools
- pydantic

## Development

When creating a new tool based on this template:

1. Copy the `dummy` directory and rename it to your tool name
2. Update all file names and class names to match your tool
3. Replace all placeholder content with your actual implementation
4. Update the `tool.yaml` file with your tool's specific details
5. Write proper tests for your tool functionality 