# Repository Instructions

## Principles

- Treat BlockAuth as a reusable third-party authentication package.
- Keep code, docs, examples, logs, and migrations generic.
- Do not add downstream product names, private hostnames, internal workflow notes, or organization-specific business rules.
- Prefer extension hooks and settings over app-specific behavior.

## Development

- Read existing patterns before changing code.
- Keep migrations package-scoped and reusable.
- Run the strongest relevant validation available before publishing changes.
- Preserve public API compatibility unless the changelog documents a breaking change.

## Security

- Do not commit secrets, private URLs, credentials, `.p8` files, or generated local artifacts.
- Do not log passwords, tokens, private keys, authorization codes, nonces, or refresh tokens.
- Use the public docs in `docs/security/security-standards.md` for security expectations.
