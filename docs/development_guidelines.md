# Development Guidelines

This document outlines the development guidelines for the CyberAgents project, including coding standards, FastAPI best practices, and tooling requirements.

## Code Quality Standards

### First-Party Code

All first-party code must adhere to strict quality standards:

- Follow PEP 8 style guide
- Include comprehensive docstrings
- Use type hints
- Pass all linting checks
- Have appropriate test coverage

### Third-Party Code

Third-party code (including node_modules, npm packages, and other dependencies) is excluded from our code quality checks:

- Linting rules do not apply to third-party code
- Code style requirements do not apply to third-party code
- Documentation requirements do not apply to third-party code
- These exclusions are enforced through configuration in .pre-commit-config.yaml and .yamllint

## Cursor IDE Configuration

The project uses Cursor IDE with specific rules for development. These rules are stored in `.cursor/.cursorrules` and include:

### Framework Configuration

- **Name**: CrewAI
- **Language**: Python
- **Configuration**: YAML
- **Schema Validation**: Pydantic
- **Testing**: pytest
- **Linting**: black, pylint, mypy, yamllint, markdownlint
- **API Framework**: FastAPI

### Dependencies

- FastAPI
- Pydantic v2
- asyncpg/aiomysql
- SQLAlchemy 2.0

## Python Development Guidelines

### Key Principles

- Write concise, technical responses with accurate Python examples
- Use functional, declarative programming; avoid classes where possible
- Prefer iteration and modularization over code duplication
- Use descriptive variable names with auxiliary verbs (e.g., `is_active`, `has_permission`)
- Use lowercase with underscores for directories and files
- Favor named exports for routes and utility functions
- Use the Receive an Object, Return an Object (RORO) pattern

### Code Style

- Use 4-space indentation
- Use type hints for all function signatures
- Prefer Pydantic models over raw dictionaries for input validation
- Avoid unnecessary curly braces in conditional statements
- Use concise, one-line syntax for simple conditional statements

### Error Handling and Validation

- Handle errors and edge cases at the beginning of functions
- Use early returns for error conditions to avoid deeply nested if statements
- Place the happy path last in the function for improved readability
- Avoid unnecessary else statements; use the if-return pattern
- Use guard clauses to handle preconditions and invalid states early
- Implement proper error logging and user-friendly error messages
- Use custom error types or error factories for consistent error handling

## FastAPI Guidelines

### File Structure

```
api/
├── routers/          # Route definitions
├── models/          # Database models
├── schemas/         # Pydantic models
├── dependencies/    # Dependency injection
├── middleware/      # Custom middleware
└── utils/          # Utility functions
```

### Best Practices

- Use functional components and Pydantic models for input validation and response schemas
- Use declarative route definitions with clear return type annotations
- Minimize `@app.on_event` decorators; prefer lifespan context managers
- Use middleware for logging, error monitoring, and performance optimization
- Use HTTPException for expected errors and model them as specific HTTP responses
- Use Pydantic's BaseModel for consistent input/output validation

### Performance Optimization

- Minimize blocking I/O operations; use async operations for database and API calls
- Implement caching for static and frequently accessed data
- Optimize data serialization and deserialization with Pydantic
- Use lazy loading techniques for large datasets
- Rely on FastAPI's dependency injection system
- Prioritize API performance metrics (response time, latency, throughput)
- Limit blocking operations in routes
- Use dedicated async functions for database and external API operations
- Structure routes and dependencies clearly

## YAML Configuration Guidelines

### Agent Definitions

- Use 4-space indentation
- Define agents with required keys: name, role, goal, tools, expected_output, and steps
- Include clearly defined I/O contracts using Markdown-style schemas or comments
- Maintain alignment between agent.yaml, agent.py, and README.md definitions

## Documentation Guidelines

### Markdown Files

- Follow markdownlint rules
- Include proper heading levels, lists, and code blocks
- Each agent must have a README.md summarizing:
  - Responsibilities
  - Schema
  - Example I/O
  - Usage instructions

## Testing Requirements

- Write tests for all new features and bug fixes
- Use pytest for testing
- Include schema validation tests
- Maintain test coverage above 80%
- Use fixtures for common test setup
- Mock external dependencies appropriately

## Security Guidelines

- No unsafe subprocesses
- No external requests without validation
- Use environment variables for sensitive data
- Implement proper authentication and authorization
- Follow OWASP security guidelines
- Regular security audits and dependency updates
