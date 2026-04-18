# BlockAuth End-to-End Testing

The E2E suite exercises every public BlockAuth endpoint over real HTTP against a live Django dev server. Two artifacts ship from the same source of truth:

- **`tests_e2e/flows/`** — pytest + `requests` suite. Runs in CI.
- **`.insomnia/collection.json`** — importable Insomnia v4 export. For interactive exploration and demos.

Both hit the same dev server spun up by `make e2e-server`.

## What is covered

| Flow | Endpoints | File |
|------|-----------|------|
| Signup → confirm → basic login → refresh | `/auth/signup/`, `/auth/signup/confirm/`, `/auth/signup/otp/resend/`, `/auth/login/basic/`, `/auth/token/refresh/` | `test_signup_basic_refresh.py` |
| Passwordless login | `/auth/login/passwordless/`, `/auth/login/passwordless/confirm/` | `test_passwordless.py` |
| Password reset + change | `/auth/password/reset/`, `/auth/password/reset/confirm/`, `/auth/password/change/` | `test_password_reset_change.py` |
| Email change | `/auth/email/change/`, `/auth/email/change/confirm/` | `test_email_change.py` |
| Wallet login (SIWE) + wallet-email-add | `/auth/login/wallet/challenge/`, `/auth/login/wallet/`, `/auth/wallet/email/add/` | `test_wallet.py` |
| Wallet link (legacy JSON-message + nonce replay) | `/auth/wallet/link/` | `test_wallet.py` |
| Passkey register + authenticate | `/auth/passkey/register/options/`, `/verify/`, `/auth/passkey/auth/options/`, `/verify/`, `/auth/passkey/credentials/` | `test_passkey.py` |
| TOTP setup → verify → disable | `/auth/totp/setup/`, `/confirm/`, `/verify/`, `/status/`, `/disable/` | `test_totp.py` |
| Step-up receipt issue + validate (RFC 9470) | `/auth/_test/stepup/issue/`, `/auth/_test/stepup/validate/` | `test_stepup.py` |

**Deferred** (scaffolded in the Insomnia collection, no pytest coverage yet): OAuth Google / Facebook / LinkedIn. They need sandbox apps with real client IDs — flip `SOCIAL_AUTH: True` in `tests_e2e/settings.py` and plug in creds when you have them.

## Prerequisites

```bash
uv sync                                    # all core deps (includes requests, pyotp, eth-account)
uv add --dev pyotp soft-webauthn           # TOTP + passkey-only; skip if you don't need those two flows
```

The TOTP flow needs `pyotp`, and the passkey flow needs `soft-webauthn`. Both tests `importorskip` so missing deps produce a skipped test, not a failure.

## Run it

Two terminals:

```bash
# Terminal A — server
make e2e-server

# Terminal B — suite
make e2e-run
```

`make e2e-server` applies migrations, then runs `python -m tests_e2e.manage runserver 0.0.0.0:8000` with `DJANGO_SETTINGS_MODULE=tests_e2e.settings`. `make e2e-run` drives pytest against `E2E_BASE_URL` (default `http://localhost:8765`). Override the env var to point at staging if you want.

Each pytest function starts by calling `POST /auth/_test/reset/` so tests are independent. SQLite is the default DB; override with `E2E_DB_PATH=/tmp/mine.sqlite3 make e2e-server`.

## Dev-only helper endpoints

Three endpoints exist **only** when `DEBUG=True` (settings guard). They must never be reachable in prod:

| Endpoint | Use |
|----------|-----|
| `GET /auth/_test/otp/<identifier>/` | Read the latest active OTP for an identifier. Bridges the "no real email/SMS in dev" gap. |
| `POST /auth/_test/reset/` | Delete all `E2EUser` + `OTP` rows. |
| `POST /auth/_test/stepup/issue/`, `POST /auth/_test/stepup/validate/` | Exercise the `blockauth.stepup` module. |

## Scripts

- `scripts/sign_siwe.py` — CLI + library. Fetches a SIWE challenge from the running server and signs it with a fixed dev-only private key so wallet-login can be driven end-to-end. Use `uv run python -m scripts.sign_siwe --base http://localhost:8765` to paste values into Insomnia.
- `scripts/webauthn_client.py` — thin wrapper around `soft-webauthn` used by the passkey pytest module.

## Using the Insomnia collection

1. Open Insomnia Desktop → **Import from File** → `.insomnia/collection.json`.
2. Select the **Local** environment (or **Dev** for staging).
3. Run requests top-to-bottom inside a flow folder. After the OTP-request step, hit `GET /auth/_test/otp/{{ email }}/` and paste the `code` into the `otp_code` env var.
4. For the wallet folder, run `uv run python -m scripts.sign_siwe` and paste `wallet_address`, `message`, `signature` into the corresponding env vars.

The Insomnia collection is a **reference artifact**. For CI-green "did every flow actually run?" coverage, rely on pytest.

## Gaps and follow-ups

- **OAuth** — intentionally deferred until sandbox provider creds exist. The Insomnia folder is empty by design; `SOCIAL_AUTH` is `False` in the E2E settings.
- **Passkey counter regression** — `soft-webauthn` increments its counter correctly, so regression detection isn't exercised. Add a raw `cryptography`-level test if you want regression coverage.

## Wallet link — how the legacy signer works

`/auth/wallet/link/` does **not** use SIWE. It uses `blockauth.utils.web3.wallet.WalletAuthenticator`, which expects a JSON-encoded message signed as an Ethereum personal message. Required shape:

```json
{"body": "Link this wallet to my account", "nonce": "<hex, min 16 chars>", "timestamp": 1712345678}
```

`WalletAuthenticator.verify_signature` enforces: (1) nonce is at least 16 chars and has not been consumed (Django cache-backed), (2) timestamp is within `WALLET_MESSAGE_TTL` (300s default), (3) recovered signer matches the supplied address. `scripts/sign_siwe.py::sign_link_message` builds and signs this payload.
