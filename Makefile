# ============================================================================
# BlockAuth Package — Development Commands
# ============================================================================

.PHONY: format lint check install lock build

# Install dependencies
install:
	@uv sync

# Regenerate lock file
lock:
	@uv lock

# Build package
build:
	@uv build

# Format code (black + isort)
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

# Run both format and lint
check: format lint
