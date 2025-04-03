# Update Dependencies and Fix Tool Compatibility

## Description

This PR updates the project dependencies and adapts the tool classes to be compatible with crewAI 0.108.0 and Pydantic v2. These changes resolve deprecation warnings and ensure the proper functioning of the tool classes with the latest package versions.

## Changes Made

1. Updated dependency versions in pyproject.toml:

   - crewai: 0.11.2 → 0.108.0
   - langchain-openai: 0.0.5 → 0.1.7
   - pydantic-core: 2.33.0 (latest)
   - Added Python version constraint: >=3.11,\<3.13

1. Updated tool classes to be compatible with crewAI 0.108.0 and Pydantic v2:

   - Updated imports from `langchain.tools` to `crewai.tools`
   - Changed `args_schema` to `input_schema`
   - Added proper type annotations to class attributes
   - Made `description` a regular attribute rather than a ClassVar
   - Added `model_config = ConfigDict(arbitrary_types_allowed=True)` to allow arbitrary types
   - Used more specific type annotations with Dict, List, and Optional

1. Added warning filters in pyproject.toml to suppress common deprecation warnings.

## Testing

- All modified tool classes have been tested with the integration test in `tests/test_crew_integration.py`
- The `test_error_handling` test is now passing successfully
- Tests that depend on the temperature parameter for o3-mini model are properly skipped

## Related Issues

- Resolves issues with unsupported temperature parameter in o3-mini model
- Fixes compatibility issues with crewAI 0.108.0 and Pydantic v2

## Screenshots (if applicable)

N/A

## Additional Notes

The integration tests now run successfully, but there are other tests in the codebase that may need additional updates not covered by this PR. The remaining warning about "open_text is deprecated" comes from the litellm package, which is a dependency of crewAI and out of our control.
