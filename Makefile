# ============================================================================
# BlockAuth Package — Development Commands
# ============================================================================

.PHONY: format lint check install

# Install dependencies
install:
	@poetry install

# Format code (black + isort)
format:
	@echo "Formatting with black..."
	@poetry run black blockauth/
	@echo "Sorting imports with isort..."
	@poetry run isort blockauth/
	@echo "Removing unused imports with autoflake..."
	@poetry run autoflake --in-place --remove-all-unused-imports --recursive blockauth/
	@echo "Done."

# Lint code (flake8)
lint:
	@echo "Linting with flake8..."
	@poetry run flake8 blockauth/
	@echo "Done."

# Run both format and lint
check: format lint
