# ============================================================================
# BlockAuth Package — Development Commands
# ============================================================================

.PHONY: format lint check install e2e-migrate e2e-server e2e-run e2e-clean

# Install dependencies
install:
	@uv sync

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

# ============================================================================
# E2E suite (see docs/E2E_TESTING.md)
# ============================================================================

# Apply migrations for the test project. Safe to re-run — SQLite file is
# reused across runs and the `_test/reset/` endpoint clears data per-flow.
e2e-migrate:
	@DJANGO_SETTINGS_MODULE=tests_e2e.settings uv run python -m tests_e2e.manage migrate --run-syncdb

# Boot the dev server that the pytest + Insomnia suites target.
# Runs in the foreground so Ctrl-C stops it cleanly; use `make -j e2e-server e2e-run`
# or a second terminal for `e2e-run`.
E2E_PORT ?= 8765

e2e-server: e2e-migrate
	@DJANGO_SETTINGS_MODULE=tests_e2e.settings uv run python -m tests_e2e.manage runserver 0.0.0.0:$(E2E_PORT)

# Run the pytest E2E flows against a live server.
e2e-run:
	@E2E_BASE_URL=$${E2E_BASE_URL:-http://localhost:$(E2E_PORT)} uv run pytest tests_e2e/flows/ -v --tb=short

# Wipe the E2E SQLite file. Useful if a migration drift creeps in.
e2e-clean:
	@rm -f tests_e2e/e2e.sqlite3
