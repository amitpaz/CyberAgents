# Dependency Fame and Shame

## Dependency Upgrade Blockers 🧐

These packages are preventing us from upgrading other dependencies. Shame!

| Package | Blocked By | Version Constraint | Shame Level |
|---------|------------|-------------------|-------------|
| `package-name` | `blocking-package` | `>=x.y.z,<a.b.c` | 🧐 or 🧐🧐 |

## Dependency Upgrade Champions 🤩

These packages are well-maintained and allow us to use their latest versions without issues. Thank you!

| Package | Current Version | Status |
|---------|----------------|--------|
| `package-name` | `x.y.z` | Successfully upgraded 🤩 |
| `package-name` | `x.y.z` | Already using recent version 🤩 |

## Special Mentions

Brief commentary on dependency trends and patterns observed during upgrade attempts.

## Maintenance Guide

This document (FAME_AND_SHAME.md) should be updated every time dependency upgrades are attempted to track:

1. **Packages that block upgrades** - When a package prevents upgrading another dependency, add it to the Blockers section with:

   - Package name (the one being blocked)
   - Blocking package name (what's blocking it)
   - Specific version constraints causing the issue
   - Shame level (🧐 for minor annoyances, 🧐🧐 for significant blockers)

1. **Successfully upgraded packages** - When a package is successfully upgraded, add or update it in the Champions section with:

   - Package name
   - New version number
   - Status (either "Successfully upgraded 🤩" or "Already using recent version 🤩")

1. **Packages that became unblocked** - If a package previously in the Blockers section is resolved (either by the blocking package relaxing its requirements or by upgrading the entire dependency chain), move it to the Champions section.

### Template Validation Checklist

Before committing changes to FAME_AND_SHAME.md, verify:

- \[ \] All table headers match the template exactly
- \[ \] Package names are enclosed in backticks
- \[ \] Version numbers follow semantic versioning format
- \[ \] Status entries end with appropriate emoji
- \[ \] Shame levels use only the defined emoji set (🧐 or 🧐🧐)
- \[ \] Numbered list in maintenance guide uses correct sequential numbering

This document serves as both documentation and motivation to keep dependencies up to date.
