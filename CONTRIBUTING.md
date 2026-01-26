# Contributing to VIGIL

Thank you for your interest in contributing to VIGIL! This document provides guidelines and information for contributors.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all backgrounds and experience levels.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/MSB-Labs/vigil/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Go version, Docker version)
   - Relevant logs or error messages

### Suggesting Features

1. Check existing issues for similar suggestions
2. Create a new issue with the `enhancement` label
3. Describe the feature and its use case
4. Explain why it would benefit VIGIL users

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `make test`
5. Run linter: `make lint`
6. Commit with clear messages: `git commit -m "Add feature X"`
7. Push to your fork: `git push origin feature/my-feature`
8. Open a Pull Request

## Development Setup

### Prerequisites

- Go 1.21+
- Docker
- Make (optional but recommended)

### Getting Started

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/vigil.git
cd vigil

# Install dependencies
go mod tidy

# Build
make build

# Build sandbox image
make docker-build

# Run tests
make test
```

## Project Structure

```
vigil/
├── cmd/vigil/          # CLI entry point
├── internal/
│   ├── cli/            # Command-line interface
│   ├── resolver/       # Package resolution
│   ├── sandbox/        # Docker sandbox
│   ├── analyzer/       # Analysis engine & rules
│   ├── store/          # Database storage
│   └── collector/      # Behavior collection
├── docker/             # Dockerfile for sandbox
└── rules/              # Default detection rules
```

## Code Style

- Follow standard Go conventions
- Run `go fmt` before committing
- Write clear comments for exported functions
- Keep functions focused and reasonably sized
- Use meaningful variable names

## Testing

- Write tests for new functionality
- Maintain or improve code coverage
- Test edge cases and error conditions

```bash
# Run all tests
make test

# Run with coverage
make test-coverage
```

## Adding Detection Rules

New detection rules go in `internal/analyzer/default_rules.go` or as custom YAML:

```yaml
- id: unique-rule-id
  name: "Human Readable Name"
  description: "What this rule detects"
  severity: high  # critical, high, medium, low, info
  category: category-name
  enabled: true
  conditions:
    - type: condition-type
      operator: operator
      values:
        - "pattern1"
        - "pattern2"
  tags: [tag1, tag2]
```

### Condition Types
- `network` - Network calls
- `file_read` - File reads
- `file_write` - File writes
- `env` - Environment variable access
- `shell` - Shell commands
- `suspicious` - Suspicious code patterns
- `install_hooks` - Install script presence

### Operators
- `contains` - Substring match
- `matches` - Regex match
- `exists` - Non-empty check
- `count_gt` - Count threshold

## Adding Ecosystem Support

To add support for a new package ecosystem (e.g., PyPI):

1. Create resolver in `internal/resolver/`
2. Update sandbox to support the ecosystem's runtime
3. Add ecosystem-specific rules
4. Update CLI to recognize the ecosystem
5. Add tests and documentation

## Questions?

- Open an issue for questions
- Tag with `question` label

Thank you for contributing to VIGIL!
