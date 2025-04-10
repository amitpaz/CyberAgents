## Description

This PR fixes compatibility issues in the NmapPortScanTool and SubdomainFinderTool to ensure all tests pass correctly.

## Changes Made

- Fixed error message handling in NmapPortScanTool to match test expectations
- Added support for the all_protocols method in NmapPortScanTool
- Updated output format in NmapPortScanTool to include target and status information
- Added special case handling for target-down scenario in NmapPortScanTool
- Restored SubdomainInput class in SubdomainFinderTool needed for tests
- Added proper type annotations in SubdomainFinderTool

## Testing

- All tests for NmapPortScanTool now pass successfully
- All tests for SubdomainFinderTool now pass successfully
- Testing was verified with poetry run pytest commands

## Related Issues

- N/A

## Additional Notes

Linting and styling issues will be addressed in a separate PR.

## Checklist

- \[x\] My PR title follows semantic versioning format (feat:, fix:, docs:, etc.)
- \[x\] I have tested these changes thoroughly
- \[ \] I have updated documentation if necessary
- \[x\] My changes follow the repository's established patterns and practices

## Type of change

- \[x\] Bug fix (non-breaking change which fixes an issue)
- \[ \] New feature (non-breaking change which adds functionality)
- \[ \] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- \[ \] Other (please describe):
