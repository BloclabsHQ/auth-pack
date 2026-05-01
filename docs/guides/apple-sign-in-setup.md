# Apple Sign-In: Credential Setup Guide

This guide walks through every credential the BlockAuth Apple flow consumes and the exact clicks to generate each in [developer.apple.com](https://developer.apple.com/account). You need a paid Apple Developer account ($99/year) — the free tier cannot enable Sign in with Apple.

## Settings the implementation reads

The Apple sub-package reads these keys from `BLOCK_AUTH_SETTINGS`:

| Setting | Required for | What it is |
|---|---|---|
| `APPLE_TEAM_ID` | web + native | 10-char Apple Developer team ID |
| `APPLE_KEY_ID` | web + native | 10-char ID of the Sign in with Apple key |
| `APPLE_PRIVATE_KEY_PEM` *or* `APPLE_PRIVATE_KEY_PATH` | web + native | Contents of the `.p8` file (or path to it) |
| `APPLE_SERVICES_ID` | web + S2S notifications | OAuth `client_id` for the web flow and webhook JWT audience |
| `APPLE_REDIRECT_URI` | web only | Must exactly match the URL registered on the Services ID |
| `APPLE_BUNDLE_IDS` | native only | List of bundle IDs accepted as `aud` on id_tokens; native authorization-code redemption uses this audience as Apple `client_id` |
| `APPLE_NOTIFICATION_TRIGGER` | S2S notifications | Dotted path to a `BaseTrigger` subclass invoked on Apple webhook events |
| `APPLE_CALLBACK_COOKIE_SAMESITE` | optional | Override SameSite on state/PKCE/nonce cookies (default `None` for cross-site form_post) |
| `APPLE_NOTIFICATION_MAX_AGE_SECONDS` | S2S notifications | Maximum accepted age of Apple `event_time` values (default 300 seconds) |
| `APPLE_NOTIFICATION_FUTURE_LEEWAY_SECONDS` | S2S notifications | Allowed future clock skew for Apple `event_time` values (default 60 seconds) |
| `APPLE_WEB_CALLBACK_RATE_LIMIT` | web callback | Per-IP `(max_requests, window_seconds)` rate limit for `/apple/callback/` |
| `APPLE_NATIVE_VERIFY_RATE_LIMIT` | native verify | Per-IP `(max_requests, window_seconds)` rate limit for `/apple/verify/` |
| `APPLE_NOTIFICATION_RATE_LIMIT` | S2S notifications | Per-IP `(max_requests, window_seconds)` rate limit for `/apple/notifications/` |

OIDC verification also reads `OIDC_JWKS_CACHE_TTL_SECONDS` and `OIDC_VERIFIER_LEEWAY_SECONDS` (shared with Google native).

---

## Step 1 — Find your Team ID

1. Sign in to [developer.apple.com/account](https://developer.apple.com/account)
2. Top-right of the page → click your name → **Membership details**
3. Copy the 10-char **Team ID**

→ This is `APPLE_TEAM_ID`.

---

## Step 2 — Create (or pick) the App ID

Skip this if your iOS/macOS app already has an explicit App ID with Sign in with Apple enabled.

1. **Certificates, IDs & Profiles → Identifiers → +**
2. Type: **App IDs** → **Continue** → **App** → **Continue**
3. **Description**: human-readable name (e.g. "Example iOS App")
4. **Bundle ID**: **Explicit**, e.g. `com.example.app`
5. Scroll to **Capabilities** → tick **Sign In with Apple**
6. Click the **Edit** button next to it → choose **Enable as a primary App ID** → **Save**
7. **Continue → Register**

→ This bundle ID goes into `APPLE_BUNDLE_IDS` (one entry per native app, as a list).

---

## Step 3 — Create the Services ID (web `client_id`)

Skip this section if you only need native (iOS/macOS) sign-in.

1. **Identifiers → +** → **Services IDs** → **Continue**
2. **Description**: e.g. "Example Web"
3. **Identifier**: reverse-DNS string, e.g. `com.example.web` (this is `APPLE_SERVICES_ID`)
4. **Continue → Register**
5. Click into the new Services ID → tick **Sign In with Apple** → **Configure**:
   - **Primary App ID**: the App ID from Step 2
   - **Domains and Subdomains**: hostnames only (no scheme, no path). Apple does **not** allow `localhost` here.
     - Production example: `auth.example.com`
     - Local dev: your reserved ngrok hostname, e.g. `ozone-proton-spinout.ngrok-free.dev` — see [Local development with an HTTPS tunnel](#local-development-with-an-https-tunnel) for how to reserve a free static domain.
   - **Return URLs**: full HTTPS callback URL. This is exactly what `APPLE_REDIRECT_URI` must equal — string-for-string.
     - Production example: `https://auth.example.com/v1/auth/apple/callback/`
     - Local dev: `https://ozone-proton-spinout.ngrok-free.dev/v1/auth/apple/callback/`
6. **Save → Continue → Save**

### No domain-association file required

> **Apple removed this step.** Older guides (and the previous version of this doc) describe a flow where you'd download `apple-developer-domain-association.txt` from a per-domain **Download** button and serve it at `/.well-known/apple-developer-domain-association.txt`. Apple retired that — there is no Download button anymore, and the domain is registered the moment you Save.
>
> If you're following an older tutorial and can't find the Download button, you're not missing anything. Skip the verification step entirely. See [Apple's current docs](https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/) for the official flow.

---

## Step 4 — Create the Sign in with Apple key (the `.p8`)

This is the private key used to sign client_secret JWTs sent to Apple's `/auth/token` endpoint.

1. **Keys → +**
2. **Key Name**: e.g. "Example Sign in with Apple"
3. Tick **Sign In with Apple** → click **Configure**
4. **Primary App ID**: same App ID from Step 2 → **Save**
5. **Continue → Register**
6. **Download the `.p8` file immediately** — Apple does not show it again. If you lose it, you must revoke the key and create a new one (and update production).
7. After download, Apple shows the **Key ID** (10 chars) → this is `APPLE_KEY_ID`.

→ Store the `.p8` and Key ID in your secret manager.

The `.p8` contents (the entire PEM block including `-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----`) go into `APPLE_PRIVATE_KEY_PEM`. Alternatively, drop the file on the server and point `APPLE_PRIVATE_KEY_PATH` at it.

---

## Step 5 — Server-to-Server Notification Endpoint (optional but recommended)

Apple sends webhooks when a user:
- Disables Sign in with Apple in iCloud settings (`consent-revoked`)
- Permanently deletes their Apple ID (`account-deleted`)
- Changes the email address backing their Apple ID (`email-disabled`, `email-enabled`)

Without S2S notifications, you'll keep stale `SocialIdentity` rows for users who revoked access. With them, the configured trigger fires and you can clean up downstream state.

### Apple-side configuration

1. Go back to your **Services ID → Sign In with Apple → Configure**
2. **Server-to-Server Notification Endpoint**: full HTTPS URL.
   - Production: `https://auth.example.com/v1/auth/apple/notifications/`
   - Local dev: `https://ozone-proton-spinout.ngrok-free.dev/v1/auth/apple/notifications/`
3. **Save**

The handler is already wired in `blockauth/apple/views.py` (route `apple/notifications/` from `blockauth.urls`). It verifies the signed payload against Apple's JWKS and dispatches to your trigger.

> **Local testing caveat:** Apple only fires S2S notifications in response to real account events (a user revoking consent in iCloud, deleting their Apple ID, etc.). There's no sandbox or "send test event" button. For local development you typically point this at the prod URL and skip wiring it up locally; if you do point it at the ngrok tunnel, expect long quiet periods unless you trigger real events.

### App-side configuration

```python
BLOCK_AUTH_SETTINGS = {
    # ...
    "APPLE_NOTIFICATION_TRIGGER": "myapp.triggers.AppleNotificationTrigger",
}
```

Implement the trigger:

```python
# myapp/triggers.py
from blockauth.triggers import BaseTrigger

class AppleNotificationTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        # context contains: event_type, sub (Apple user id), event_time
        # (normalized Unix seconds),
        # and user_id if BlockAuth matched a SocialIdentity row.
        event = context["event_type"]
        if event in ("account-deleted", "consent-revoked"):
            # delete or disable the linked account
            ...
        elif event in ("email-disabled", "email-enabled"):
            # update email_verified state
            ...
```

The endpoint is **safe to expose without further auth** — the request body is a JWT signed by Apple and validated against Apple's published JWKS before the trigger fires. BlockAuth also rejects stale or future `event_time` values, suppresses replayed notifications before mutation or trigger dispatch, and applies a per-IP throttle to malformed or excessive traffic.

Use a shared Django cache backend such as Redis or Memcached in production. Django's local-memory cache is process-local, so it is not sufficient for cluster-wide Apple notification replay suppression or per-IP throttling across multiple workers.

---

## Step 6 — Wire it into Django

```python
# settings.py
import os

BLOCK_AUTH_SETTINGS = {
    # ... your existing settings ...

    "FEATURES": {
        # ... existing flags ...
        "APPLE_LOGIN": True,
    },

    # Web flow
    "APPLE_TEAM_ID":         "ABCD123456",
    "APPLE_SERVICES_ID":     "com.example.web",
    # Production:
    "APPLE_REDIRECT_URI":    "https://auth.example.com/v1/auth/apple/callback/",
    # Local dev (must equal the Return URL registered on the Services ID):
    # "APPLE_REDIRECT_URI":  "https://ozone-proton-spinout.ngrok-free.dev/v1/auth/apple/callback/",

    # Key (used by both web and native)
    "APPLE_KEY_ID":          "EFGH789012",
    "APPLE_PRIVATE_KEY_PEM": os.environ["APPLE_PRIVATE_KEY_PEM"],
    # OR:
    # "APPLE_PRIVATE_KEY_PATH": "/etc/secrets/AuthKey_EFGH789012.p8",

    # Native flow
    "APPLE_BUNDLE_IDS":      ["com.example.app"],

    # Optional S2S notifications
    "APPLE_NOTIFICATION_TRIGGER": "myapp.triggers.AppleNotificationTrigger",
    "APPLE_NOTIFICATION_MAX_AGE_SECONDS": 300,
    "APPLE_NOTIFICATION_FUTURE_LEEWAY_SECONDS": 60,
    "APPLE_NOTIFICATION_RATE_LIMIT": (60, 60),
    "APPLE_NATIVE_VERIFY_RATE_LIMIT": (30, 60),
    "APPLE_WEB_CALLBACK_RATE_LIMIT": (30, 60),
}
```

For Docker / Kubernetes deployments, mount the `.p8` as a secret file and use `APPLE_PRIVATE_KEY_PATH`. For Heroku/Render-style platforms with no filesystem, paste the PEM into an env var and use `APPLE_PRIVATE_KEY_PEM`.

---

## Local development with an HTTPS tunnel

Apple won't accept `localhost` as a domain or as a Return URL on the Services ID, so testing the **web flow** locally requires an HTTPS tunnel pointing at the backend that serves `blockauth.urls`. ngrok is the path of least resistance.

### Where the tunnel terminates

**The tunnel must point at the backend, not the frontend.** Apple's `form_post` callback hits `APPLE_REDIRECT_URI`, which is a server route at `/v1/auth/apple/callback/`. The frontend is irrelevant to that exchange — it only kicks off the flow and receives the final post-login redirect.

If your backend is behind a reverse proxy or API gateway, point the tunnel at that public local entry point. If you run Django directly, point the tunnel at the Django port.

```
Browser  ──→  Apple  ──form_post──→  tunnel (example.ngrok-free.dev)
                                            ↓
                                     reverse proxy or Django
                                            ↓
                                     blockauth.apple views
```

Do not point the tunnel at the frontend. Apple's `form_post` callback is a server-side route, and the cookies used for state / PKCE / nonce are issued by the backend.

### Stable hostname is mandatory

The whole setup below is built around a **reserved static ngrok domain** so the hostname stays the same across `ngrok` restarts. Without that, every restart hands you a new random subdomain and you'd be re-editing the Services ID and re-setting `APPLE_REDIRECT_URI` each time. ngrok gives every account **one free static domain** (on `*.ngrok-free.dev`) — that's all we need.

> The **native flow** (`POST /apple/verify/`) doesn't need a tunnel — it has no redirect URI. As long as `APPLE_TEAM_ID`, `APPLE_KEY_ID`, the `.p8`, and `APPLE_BUNDLE_IDS` are set, a native app can post a real id_token straight at a locally reachable backend.

### 1. Install ngrok on macOS

```bash
brew install ngrok
```

Sign up at [ngrok.com](https://dashboard.ngrok.com/signup), copy the authtoken from the dashboard, and register it once:

```bash
ngrok config add-authtoken <your-token>
```

### 2. Reserve a free static domain

In the ngrok dashboard:

1. Go to the domains section and create a new static domain.
2. The free tier offers one auto-generated subdomain on `ngrok-free.dev` (e.g. `ozone-proton-spinout.ngrok-free.dev`). Click **Create Domain**.
3. Copy the full hostname — this is your stable URL. Use the same one in every example below.

(Throughout this doc we use `ozone-proton-spinout.ngrok-free.dev` as the placeholder — substitute your reserved domain everywhere.)

### 3. Start the tunnel pointed at the backend

Make sure the backend is running locally. Then:

```bash
ngrok http --url=https://ozone-proton-spinout.ngrok-free.dev 8000
```

Replace `8000` with the local port that serves the Apple callback route. ngrok prints `Forwarding https://ozone-proton-spinout.ngrok-free.dev -> http://localhost:8000` when it is connected.

The `--url` flag pins the tunnel to your reserved hostname. Without it ngrok rotates the subdomain on every start, which defeats the point. Keep the terminal open — closing it kills the tunnel, but the hostname stays reserved on your account so the next `ngrok http --url=...` reconnects to the same URL.

> `--url` replaces the older `--domain`/`--scheme`/`--remote-addr` flags as of ngrok agent v3.16.0. If you see `Flag --domain has been deprecated, use --url instead`, that's why — and note that `--url` takes the **full URL with scheme** (`https://...`), not just the hostname.

### 4. Check reverse-proxy routing (one-time)

If your local stack uses an API gateway, make sure the unauthenticated Apple routes are forwarded to Django. These paths are relative to wherever you mount `blockauth.urls`:

- `GET /apple/`
- `POST /apple/callback/`
- `POST /apple/verify/`
- `POST /apple/notifications/`

The callback and notification endpoints must not require an existing user JWT. Apple reaches them before your app has authenticated the user, and the notification endpoint authenticates the request by verifying Apple's signed payload.

### 5. Wire the tunnel into the Apple flow

1. **Step 3 (Services ID)** — register the static hostname:
   - **Domains and Subdomains**: `ozone-proton-spinout.ngrok-free.dev`
   - **Return URLs**: `https://ozone-proton-spinout.ngrok-free.dev/v1/auth/apple/callback/`
2. **Step 6 (settings)** — set `APPLE_REDIRECT_URI` in local settings to the tunnel URL, byte-for-byte the same Return URL registered above:

   ```bash
   APPLE_REDIRECT_URI=https://ozone-proton-spinout.ngrok-free.dev/v1/auth/apple/callback/
   ```
3. Add the ngrok host to Django's `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS`:

   ```python
   ALLOWED_HOSTS = ["localhost", "127.0.0.1", "ozone-proton-spinout.ngrok-free.dev"]
   CSRF_TRUSTED_ORIGINS = ["https://ozone-proton-spinout.ngrok-free.dev"]
   ```
4. Drive the flow from the browser: open `https://ozone-proton-spinout.ngrok-free.dev/apple/` → `appleid.apple.com` → Apple `form_post`s the callback back through the tunnel → your backend → blockauth's Apple callback view.

The state/PKCE/nonce cookies are issued with `SameSite=None` (Apple's `form_post` is cross-site), which browsers only honor over HTTPS — plain `http://localhost` would silently drop them even if Apple allowed it.

### Can the registered URL be changed later?

Yes. The Services ID's **Domains and Subdomains** and **Return URLs** are editable at any time: **Identifiers → your Services ID → Sign In with Apple → Configure → Save**. Changes apply within seconds and don't require Apple review. Since Apple no longer requires the domain-association file, there's no per-domain verification round-trip — adding a new hostname is purely a Save.

Even so, the recommended pattern is: **reserve one static ngrok domain per developer, register it on the Services ID once, and leave it alone.** Other workable static-hostname options if `ngrok-free.dev` isn't acceptable:

- **Paid ngrok plan**: reserve a custom domain like `apple-dev.example.com` (Dashboard → Domains → + New Domain → bring-your-own), then `ngrok http --url=https://apple-dev.example.com 8000`.
- **Cloudflare Tunnel (free)**: a named tunnel under a domain you own gives the same stability without ngrok at all.

---

## Verification checklist

Before declaring it done:

- [ ] Team ID, Key ID, Services ID, and Bundle ID copied into your secret manager
- [ ] `.p8` file uploaded to your secret manager (Apple will not let you re-download)
- [ ] `APPLE_REDIRECT_URI` matches the **Return URL** registered on the Services ID exactly (trailing slash, scheme, host, port — all of it)
- [ ] Web flow: `GET /v1/auth/apple/` redirects to `appleid.apple.com`
- [ ] Web flow: callback completes and a `SocialIdentity` row is created with `provider="apple"`
- [ ] Native flow: `POST /v1/auth/apple/verify/` with a real id_token from an iOS app returns 200 with auth tokens
- [ ] (If enabled) S2S endpoint `POST /v1/auth/apple/notifications/` accepts an Apple-signed payload and rejects an unsigned one with 401

---

## Troubleshooting

**`invalid_client` from Apple's `/auth/token`** — usually one of:
- `APPLE_KEY_ID` doesn't match the `.p8` file you uploaded
- `APPLE_TEAM_ID` wrong
- `APPLE_SERVICES_ID` wrong, or the Services ID isn't enabled for Sign in with Apple
- `.p8` file corrupt or wrong key (expired/revoked)

**`invalid_grant`** — the authorization `code` was already used or expired (codes are one-time, ~5 min TTL). Common when refreshing the page on the callback URL.

**`Invalid redirect_uri`** — `APPLE_REDIRECT_URI` does not match the Return URL on the Services ID byte-for-byte. Apple is strict about trailing slashes.

**`nonce_mismatch` on native verify** — the iOS app and the server disagree on the nonce. The app must send the **raw** nonce; Apple hashes it before putting it in the id_token. The server hashes it again and compares.

**S2S notifications never fire** — check that the Services ID's S2S endpoint URL is reachable from the public internet (Apple doesn't accept self-signed certs or private IPs) and that you saved the config.
