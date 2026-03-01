# Contributing to MemSift

Thank you for your interest in contributing to MemSift! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Pull Request Guidelines](#pull-request-guidelines)

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Welcome newcomers and help them learn

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/memsift.git
   cd memsift
   ```
3. **Set up the development environment** (see below)
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- git

### Installation

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

3. Install pre-commit hooks (optional but recommended):
   ```bash
   pre-commit install
   ```

### Project Structure

```
memsift/
├── memsift/              # Source code
│   ├── core/             # Core analysis engine
│   ├── plugins/          # Analysis plugins
│   └── utils/            # Utility modules
├── tests/                # Test suite
├── docs/                 # Documentation
└── scripts/              # Development scripts
```

## Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/) style guidelines
- Use [type hints](https://docs.python.org/3/library/typing.html) for all function signatures
- Maximum line length: 100 characters
- Use double quotes for strings

### Type Hints

```python
# Good
def process_data(data: bytes, min_length: int = 4) -> list[tuple[int, str]]:
    ...

# Avoid
def process_data(data, min_length=4):
    ...
```

### Documentation

- Add docstrings to all public classes and functions
- Use Google-style docstrings:
  ```python
  def analyze(self, plugin_names: list[str] | None = None) -> AnalysisResult:
      """Run analysis with specified or all enabled plugins.

      Args:
          plugin_names: List of plugin names to run. If None, runs all enabled plugins.

      Returns:
          AnalysisResult containing all findings and statistics.
      """
  ```

### Code Organization

- Keep functions focused (ideally < 50 lines)
- Break complex functions into smaller helper functions
- Use meaningful variable and function names
- Avoid magic numbers - use named constants

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=memsift --cov-report=html

# Run specific test file
pytest tests/test_parser.py

# Run specific test
pytest tests/test_parser.py::TestMemoryParser::test_parser_read_at
```

### Writing Tests

- Write tests for all new features
- Aim for ≥80% code coverage
- Use descriptive test names: `test_<method>_<scenario>_<expected_result>`
- Use fixtures for common setup

```python
def test_parser_read_at_bounds(self, temp_raw_file: Path) -> None:
    """Test read bounds checking."""
    parser = MemoryParser(temp_raw_file)
    with parser.open():
        with pytest.raises(ValueError, match="exceeds file bounds"):
            parser.read_at(0, parser.size + 100)
```

### Test Categories

- **Unit tests**: Test individual functions/classes
- **Integration tests**: Test component interactions
- **End-to-end tests**: Test complete workflows

## Submitting Changes

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new crypto scanner plugin
fix: resolve memory leak in string extraction
docs: update API documentation
test: add tests for network analyzer
refactor: simplify pattern matching logic
chore: update dependencies
```

### Before Submitting

1. Run the test suite:
   ```bash
   pytest
   ```

2. Run linting:
   ```bash
   ruff check memsift/
   mypy memsift/
   ```

3. Update documentation if needed

4. Add yourself to the contributors list (if applicable)

## Pull Request Guidelines

### PR Title

Use the same format as commit messages:
```
feat: add support for ELF core dumps
```

### PR Description

Include:
- **What** changes were made
- **Why** the changes are needed
- **How** the changes were tested
- Related issues (e.g., "Fixes #123")

### Review Process

1. All PRs require at least one review
2. Address review feedback promptly
3. CI checks must pass before merging

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Type hints added
- [ ] No linting errors
- [ ] Commit messages follow conventions

## Areas for Contribution

### High Priority

- Additional memory dump format support
- Performance optimizations
- New analysis plugins
- Improved detection algorithms

### Medium Priority

- Documentation improvements
- Test coverage increases
- CI/CD enhancements
- Developer tooling

### Low Priority

- Code refactoring
- Minor bug fixes
- UI/UX improvements

## Questions?

- Open an issue for bugs or feature requests
- Use GitHub Discussions for general questions
- Check existing documentation first

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
