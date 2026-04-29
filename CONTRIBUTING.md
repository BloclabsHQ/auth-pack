# Contributing to BlockAuth

Thanks for your interest in contributing to BlockAuth.

## Getting Started

```bash
# Clone the repo
git clone https://github.com/BloclabsHQ/auth-pack.git
cd auth-pack

# Install uv (if not installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Run tests
uv run pytest

# Format checks
uv run black --check blockauth
uv run isort --check-only blockauth
```

## Development Workflow

1. Fork the repo and create a branch from `dev`
2. Make your changes
3. Run `uv run black --check blockauth` and `uv run isort --check-only blockauth`
4. Run `uv run pytest` to verify tests pass
5. Open a PR against `dev`

## Branch Strategy

- `main` — stable releases only
- `dev` — active development, PRs target this branch

## Code Standards

- **Format**: black (120 char line length) + isort
- **Lint**: flake8
- **Security**: See [Security Standards](docs/security/security-standards.md)

Key rules:
- No hardcoded secrets or credentials
- No sensitive data in logs (passwords, tokens, keys)
- Use `hmac.compare_digest()` for cryptographic comparisons
- Use `secrets` module for random generation
- Pin JWT algorithms on decode

## Commit Messages

Follow conventional commits:
```
feat: add new authentication method
fix: resolve timing attack in KDF verification
docs: update API endpoint documentation
chore: bump dependency versions
```

## Security

If you discover a security vulnerability, please do NOT open a public issue. Email security@bloclabs.com instead.

## Versioning

We use [Semantic Versioning](https://semver.org/). Version is tracked in:
- `pyproject.toml` → `version`
- `blockauth/__init__.py` → `__version__`

Both must be updated together.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
