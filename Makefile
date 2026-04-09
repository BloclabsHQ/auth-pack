# ============================================================================
# BlockAuth Package — Development Commands
# ============================================================================

.PHONY: format lint check install test build clean typecheck help

.DEFAULT_GOAL := help

# Install dependencies
install:
	@uv sync

# Format code (black + isort + autoflake)
format:
	@echo "Formatting with black..."
	@uv run black blockauth/
	@echo "Sorting imports with isort..."
	@uv run isort blockauth/
	@echo "Removing unused imports with autoflake..."
	@uv run autoflake --in-place --remove-all-unused-imports --recursive blockauth/
	@echo "Done."

# Lint code (flake8)
lint:
	@echo "Linting with flake8..."
	@uv run flake8 blockauth/
	@echo "Done."

# Run tests
test:
	@echo "Running tests..."
	@uv run pytest
	@echo "Done."

# Build package
build:
	@echo "Building package..."
	@uv build
	@echo "Done."

# Type check
typecheck:
	@echo "Running type checks..."
	@uv run mypy blockauth/ --ignore-missing-imports
	@echo "Done."

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf dist/ build/ *.egg-info .pytest_cache/ .mypy_cache/ .ruff_cache/ htmlcov/ .coverage
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "Done."

# Run both format and lint
check: format lint

# Show available targets
help:
	@echo "Available targets:"
	@echo "  install    - Install dependencies (uv sync)"
	@echo "  format     - Format code (black + isort + autoflake)"
	@echo "  lint       - Lint code (flake8)"
	@echo "  check      - Run format + lint"
	@echo "  test       - Run tests (pytest)"
	@echo "  build      - Build package (uv build)"
	@echo "  typecheck  - Run type checks (mypy)"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this help"
