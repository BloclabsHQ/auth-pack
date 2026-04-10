# Contributing to BlockAuth

## Breaking Changes

A breaking change is any modification that forces consumers to update their code.

### What Counts as Breaking

| Breaking | Not Breaking |
|----------|-------------|
| Changing `error_code` value in any response | Adding a new endpoint |
| Changing HTTP status code on any existing response | Adding a new optional serializer field |
| Renaming or removing a public class, method, or setting | Adding a new feature flag (default `True`) |
| Changing a `BLOCK_AUTH_SETTINGS` default that affects behavior | Fixing a 500 to return the correct 4xx |
| Removing or renaming a trigger context key | Adding a new trigger |
| Making a previously optional serializer field required | Adding new error codes for new endpoints |
| Changing `authentication_types` enum values | Internal refactors with no contract change |

**Special rule:** If the current behavior is a bug but consumers might depend on it, treat it as a breaking change regardless. Do not silently change observable behavior.

### The 5-Step Process

When a PR touches anything in the Breaking column above:

1. **Label** — add the `breaking-change` label to the PR on GitHub
2. **CHANGELOG** — add an entry under `## [Unreleased]` → `### Breaking Changes`, one sentence per change with a migration note
3. **Version bump** — update `pyproject.toml` and `blockauth/__init__.py`. Pre-1.0: breaking = minor bump. Post-1.0: breaking = major bump.
4. **Release note** — when tagging, the GitHub release body must include a `## Breaking Changes` section with migration steps
5. **Never silent** — every observable behavior change gets a CHANGELOG entry, even small ones

### Versioning Rules

| Change type | Version bump |
|-------------|-------------|
| Bug fix (no contract change) | Patch — `0.4.0` → `0.4.1` |
| New feature | Minor — `0.4.0` → `0.5.0` |
| Breaking change (pre-1.0) | Minor — `0.4.0` → `0.5.0` |
| Breaking change (post-1.0) | Major — `1.0.0` → `2.0.0` |

## Development

```bash
uv sync            # install deps
uv run pytest      # run tests
make check         # format + lint
uv build           # build package
```

## Releasing

Bump version in `pyproject.toml` and `blockauth/__init__.py`, then:

```bash
git tag v0.5.0 && git push origin v0.5.0
```
