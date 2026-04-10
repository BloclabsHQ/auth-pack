# Breaking Change Policy — Design Spec

**Date:** 2026-04-09
**Status:** Approved (revised)

---

## Problem

BlockAuth has no formal process for identifying, communicating, or versioning breaking changes. Changes that affect consumers (error codes, HTTP status, public APIs, settings defaults) have been landing silently. There is no PR template, no CHANGELOG, and no label convention.

---

## Scope

All changes to `blockauth` that affect downstream consumers: services that import the package, APIs that respond to HTTP clients, and developers configuring `BLOCK_AUTH_SETTINGS`.

Out of scope: internal refactors, test-only changes, documentation updates.

---

## Where Content Lives

`CLAUDE.md` is behavioral instruction for the AI — not a policy document. The breaking change policy is team process documentation and belongs in `.github/CONTRIBUTING.md`. `CLAUDE.md` gets one line pointing there.

| Content | Location |
|---------|----------|
| Breaking/not-breaking table | `.github/CONTRIBUTING.md` |
| 5-step process | `.github/CONTRIBUTING.md` |
| Running change history | `CHANGELOG.md` (repo root) |
| PR checklist | `.github/PULL_REQUEST_TEMPLATE.md` |
| `breaking-change` label | GitHub (created once via `gh`) |
| AI behavioral rule | `CLAUDE.md` — one line only |

The PR template is the strongest enforcement: it fires at PR creation regardless of what the AI remembered.

---

## What Counts as a Breaking Change

| Breaking | Not Breaking |
|----------|-------------|
| Changing `error_code` value in any response | Adding a new endpoint |
| Changing HTTP status code on any existing response | Adding a new optional serializer field |
| Renaming or removing a public class, method, or setting | Adding a new feature flag (default `True`) |
| Changing a `BLOCK_AUTH_SETTINGS` default that affects behavior | Fixing a 500 to return the correct 4xx |
| Removing or renaming a trigger context key | Adding a new trigger |
| Making a previously optional serializer field required | Adding new error codes for new endpoints |
| Changing `authentication_types` enum values | Internal refactors with no contract change |

**Special rule:** If the current behavior is a bug but consumers might depend on it, document it as a breaking change regardless. Do not silently change observable behavior.

---

## Process — 5 Steps

When a PR touches anything in the "Breaking" column:

1. **Label** — add `breaking-change` label to the PR
2. **CHANGELOG** — add entry under `## [Unreleased]` → `### Breaking Changes`, one sentence + migration note
3. **Version bump** — update `pyproject.toml` and `blockauth/__init__.py`. Pre-1.0: breaking = minor bump. Post-1.0: breaking = major bump.
4. **Release note** — when tagging, the GitHub release body must include a `## Breaking Changes` section with migration steps
5. **Never silent** — every observable behavior change gets a CHANGELOG entry

---

## Artifacts

### `.github/CONTRIBUTING.md`
Full policy: the breaking/not-breaking table, the 5-step process, versioning rules. The authoritative reference for humans and the AI when it needs detail.

### `.github/PULL_REQUEST_TEMPLATE.md`
Every PR answers a breaking change checkbox with a migration notes field. This is the enforcement point — it fires at PR creation.

### `CHANGELOG.md`
Keep a Changelog format. Backfill v0.3.0 and v0.4.0 with known changes. Structure:
```
## [Unreleased]
### Breaking Changes
### Added
### Fixed

## [0.4.0] - 2026-04-09
## [0.3.0] - 2026-04-08
```

### `breaking-change` GitHub label
Red (`#d73a4a`). Created once via `gh label create`. Makes breaking PRs visible in the PR list and in releases.

### `CLAUDE.md` — one line added to Commands section
```
Breaking changes — check `.github/CONTRIBUTING.md` before opening any PR.
```

---

## Files Changed

| File | Change |
|------|--------|
| `.github/CONTRIBUTING.md` | Create — full policy, table, 5-step process |
| `CHANGELOG.md` | Create — backfilled v0.3.0 and v0.4.0 |
| `.github/PULL_REQUEST_TEMPLATE.md` | Create — breaking change checkbox |
| `CLAUDE.md` | Add one-line pointer to CONTRIBUTING.md |
| GitHub label `breaking-change` | Create via `gh` CLI |

---

## Out of Scope

- Automated version bumping (conventional commits, semantic-release) — future
- CI enforcement (required label on every PR) — future
- Deprecation window / sunset policy — not needed at current scale
