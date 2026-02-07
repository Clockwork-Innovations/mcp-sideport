# Contributing to mcp-sideport

Thanks for your interest in contributing!

## Development Setup

```bash
# Clone the repo
git clone https://github.com/Clockwork-Innovations/mcp-sideport.git
cd mcp-sideport

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in dev mode with all dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
```

## Code Style

We use [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
# Check for issues
ruff check src/ tests/
ruff format --check src/ tests/

# Auto-fix
ruff check src/ tests/ --fix
ruff format src/ tests/
```

## Pull Request Process

1. Fork the repo and create a feature branch
2. Make your changes
3. Ensure tests pass and code is formatted
4. Submit a PR with a clear description of the changes

## Reporting Issues

Please open an issue on GitHub with:
- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Python version and OS
