# OAuth Providers

BlockAuth supports Google, Facebook, and LinkedIn OAuth2 login. Each provider uses a redirect-based flow and requires the `SOCIAL_AUTH` feature flag.

## Provider Configuration

Configure providers in `BLOCK_AUTH_SETTINGS['AUTH_PROVIDERS']`:

```python
import os

BLOCK_AUTH_SETTINGS = {
    'AUTH_PROVIDERS': {
        'GOOGLE': {
            'CLIENT_ID': os.getenv('GOOGLE_CLIENT_ID'),
            'CLIENT_SECRET': os.getenv('GOOGLE_CLIENT_SECRET'),
            'REDIRECT_URI': os.getenv('GOOGLE_REDIRECT_URI'),
        },
        'LINKEDIN': {
            'CLIENT_ID': os.getenv('LINKEDIN_CLIENT_ID'),
            'CLIENT_SECRET': os.getenv('LINKEDIN_CLIENT_SECRET'),
            'REDIRECT_URI': os.getenv('LINKEDIN_REDIRECT_URI'),
        },
        'FACEBOOK': {
            'CLIENT_ID': os.getenv('FACEBOOK_CLIENT_ID'),
            'CLIENT_SECRET': os.getenv('FACEBOOK_CLIENT_SECRET'),
            'REDIRECT_URI': os.getenv('FACEBOOK_REDIRECT_URI'),
        },
    },
}
```

!!! warning
    Never hardcode client secrets. Use environment variables or a secrets manager.

Only providers with configuration present will have their URL patterns registered.

## OAuth Flow

All providers follow the same pattern:

1. **Initiate**: `GET /auth/{provider}/` redirects the user to the provider's consent page
2. **Callback**: Provider redirects back to `GET /auth/{provider}/callback/` with an authorization code
3. **Token exchange**: BlockAuth exchanges the code for user info and returns JWT tokens

## Google

### Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create OAuth 2.0 credentials (Web application)
3. Add your redirect URI: `https://yourdomain.com/auth/google/callback/`
4. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI`

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/google/` | Redirects to Google consent |
| GET | `/auth/google/callback/` | Handles Google callback |

## Facebook

### Setup

1. Go to [Facebook Developers](https://developers.facebook.com/)
2. Create an app and add Facebook Login
3. Add your redirect URI in Valid OAuth Redirect URIs
4. Set `FACEBOOK_CLIENT_ID`, `FACEBOOK_CLIENT_SECRET`, and `FACEBOOK_REDIRECT_URI`

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/facebook/` | Redirects to Facebook consent |
| GET | `/auth/facebook/callback/` | Handles Facebook callback |

## LinkedIn

### Setup

1. Go to [LinkedIn Developer Portal](https://developer.linkedin.com/)
2. Create an app and add Sign In with LinkedIn using OpenID Connect
3. Add your redirect URI
4. Set `LINKEDIN_CLIENT_ID`, `LINKEDIN_CLIENT_SECRET`, and `LINKEDIN_REDIRECT_URI`

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/linkedin/` | Redirects to LinkedIn consent |
| GET | `/auth/linkedin/callback/` | Handles LinkedIn callback |

## Callback Response

On successful OAuth login, BlockAuth creates or retrieves the user and returns JWT tokens:

```json
{
  "access": "eyJ...",
  "refresh": "eyJ..."
}
```

If the user doesn't exist, a new account is created with the email from the provider.

## Troubleshooting

**Redirect URI mismatch**: Ensure the redirect URI in your provider dashboard matches the one in `BLOCK_AUTH_SETTINGS` exactly, including trailing slashes and protocol (HTTPS in production).

**ALLOWED_HOSTS**: Your callback domain must be in Django's `ALLOWED_HOSTS`.

**HTTPS required**: Most providers require HTTPS redirect URIs in production. Use `SECURE_SSL_REDIRECT = True`.
