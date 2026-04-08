# Custom JWT Claims Provider Guide

## Overview

BlockAuth provides a powerful and flexible JWT token management system that allows projects to add custom claims to JWT tokens. This is achieved through a pluggable claims provider architecture that integrates seamlessly with the existing authentication flow.

## Table of Contents
- [Architecture](#architecture)
- [Creating a Custom Claims Provider](#creating-a-custom-claims-provider)
- [Registering Your Provider](#registering-your-provider)
- [Complete Example](#complete-example)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Architecture

The JWT claims system uses a provider pattern where multiple claims providers can be registered with the JWT manager. When a token is generated, the JWT manager:

1. Creates standard JWT claims (user_id, exp, iat, type)
2. Calls each registered claims provider to collect custom claims
3. Merges all claims into the final token payload

```
Token Generation Flow:
User Login → JWT Manager → Claims Provider 1 → Claims Provider 2 → ... → Final Token
```

## Creating a Custom Claims Provider

### Step 1: Define Your Claims Provider Class

Create a class that inherits from `CustomClaimsProvider` and implements both `get_custom_claims` and `validate_custom_claims`:

```python
# myapp/jwt_claims.py
import logging
from typing import Dict, Any

from blockauth.jwt.interfaces import CustomClaimsProvider

logger = logging.getLogger(__name__)


class MyCustomClaimsProvider(CustomClaimsProvider):
    """
    Custom JWT claims provider for MyApp.

    Must implement:
    - get_custom_claims(user) -> Dict[str, Any]
    - validate_custom_claims(claims) -> bool
    """

    def get_custom_claims(self, user) -> Dict[str, Any]:
        """
        Generate custom claims for a user.

        Args:
            user: User object (Django User model instance)

        Returns:
            Dict[str, Any]: Dictionary of custom claims to add to JWT
        """
        try:
            # Check if user is valid
            if not user:
                logger.warning("No user provided for claims generation")
                return {}

            # Build your custom claims
            claims = {
                "organization_id": str(user.organization_id) if hasattr(user, 'organization_id') else None,
                "role": user.role if hasattr(user, 'role') else "user",
                "permissions": self._get_user_permissions(user),
                "subscription_tier": self._get_subscription_tier(user),
                # Add any other custom claims your application needs
            }

            # Remove None values to keep token clean
            claims = {k: v for k, v in claims.items() if v is not None}

            return claims

        except Exception as e:
            logger.error(f"Error generating custom claims: {e}")
            return {}

    def _get_user_permissions(self, user):
        """Helper method to get user permissions"""
        # Implement your permission logic
        if hasattr(user, 'user_permissions'):
            return list(user.user_permissions.values_list('codename', flat=True))
        return []

    def _get_subscription_tier(self, user):
        """Helper method to get subscription tier"""
        # Implement your subscription logic
        if hasattr(user, 'subscription'):
            return user.subscription.tier
        return "free"

    def validate_custom_claims(self, claims: Dict[str, Any]) -> bool:
        """
        Validate custom claims during token verification.

        Called by JWTTokenManager.decode_token() for each provider.
        Return False to reject the token.
        """
        # Example: ensure role claim is present
        return "role" in claims
```

### Step 2: Create a Registration Function

Add a registration function that registers your provider with the JWT manager:

```python
# myapp/jwt_claims.py (continued)

def register_myapp_claims_provider():
    """
    Register the custom claims provider with blockauth

    Returns:
        bool: True if registration was successful, False otherwise
    """
    try:
        from blockauth.jwt.token_manager import jwt_manager

        # Create and register your claims provider
        provider = MyCustomClaimsProvider()
        jwt_manager.register_claims_provider(provider)

        logger.info(f"Successfully registered {provider.name} claims provider")
        return True

    except ImportError:
        logger.warning("blockauth not available, skipping claims provider registration")
        return False
    except Exception as e:
        logger.error(f"Failed to register claims provider: {e}")
        return False
```

## Registering Your Provider

### Option 1: Register in Django App Configuration (Recommended)

Register your claims provider when your Django app starts up:

```python
# myapp/apps.py
from django.apps import AppConfig
import logging

logger = logging.getLogger(__name__)


class MyAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'myapp'

    def ready(self):
        """Called when Django starts up"""
        # Register JWT claims provider
        try:
            from .jwt_claims import register_myapp_claims_provider

            if register_myapp_claims_provider():
                logger.info("Successfully registered MyApp JWT claims provider")
            else:
                logger.warning("Failed to register MyApp JWT claims provider")
        except Exception as e:
            logger.error(f"Error registering JWT claims provider: {e}")
```

### Option 2: Manual Registration

You can also manually register your provider in your application's initialization code:

```python
# In your initialization script or management command
from myapp.jwt_claims import register_myapp_claims_provider

# Register the provider
if register_myapp_claims_provider():
    print("Claims provider registered successfully")
```

## Complete Example

Here's a complete example for a multi-tenant SaaS application:

```python
# saas/jwt_claims.py
import logging
from typing import Dict, Any
from django.core.cache import cache

logger = logging.getLogger(__name__)


class SaaSClaimsProvider:
    """
    JWT claims provider for multi-tenant SaaS platform
    """

    def __init__(self):
        self.name = "saas"
        self.description = "Multi-tenant SaaS claims"

    def get_custom_claims(self, user) -> Dict[str, Any]:
        """
        Generate SaaS-specific claims
        """
        try:
            if not user:
                return {}

            # Try to get cached claims first (for performance)
            cache_key = f"jwt_claims:{user.id}"
            cached_claims = cache.get(cache_key)
            if cached_claims:
                return cached_claims

            claims = {}

            # Add tenant information
            if hasattr(user, 'tenant'):
                claims['tenant_id'] = str(user.tenant.id)
                claims['tenant_slug'] = user.tenant.slug
                claims['tenant_tier'] = user.tenant.subscription_tier

            # Add user role within tenant
            if hasattr(user, 'tenant_role'):
                claims['tenant_role'] = user.tenant_role.name
                claims['is_tenant_admin'] = user.tenant_role.is_admin

            # Add feature flags
            claims['features'] = self._get_enabled_features(user)

            # Add API rate limits based on subscription
            claims['api_rate_limit'] = self._get_rate_limit(user)

            # Cache the claims for 5 minutes
            cache.set(cache_key, claims, 300)

            return claims

        except Exception as e:
            logger.error(f"Error generating SaaS claims: {e}")
            return {}

    def _get_enabled_features(self, user):
        """Get list of enabled features for user's tenant"""
        if hasattr(user, 'tenant'):
            return list(user.tenant.enabled_features.values_list('code', flat=True))
        return ['basic']

    def _get_rate_limit(self, user):
        """Get API rate limit based on subscription"""
        tier_limits = {
            'free': 100,
            'starter': 1000,
            'professional': 5000,
            'enterprise': 50000
        }

        if hasattr(user, 'tenant'):
            tier = user.tenant.subscription_tier
            return tier_limits.get(tier, 100)
        return 100


def register_saas_claims_provider():
    """Register SaaS claims provider"""
    try:
        from blockauth.jwt.token_manager import jwt_manager

        provider = SaaSClaimsProvider()
        jwt_manager.register_claims_provider(provider)

        logger.info("SaaS claims provider registered")
        return True

    except Exception as e:
        logger.error(f"Failed to register SaaS claims provider: {e}")
        return False


# Optional: Function to invalidate cached claims when user/tenant changes
def invalidate_user_claims_cache(user_id: str):
    """
    Invalidate JWT claims cache for a user

    Call this when user's tenant, role, or subscription changes
    """
    cache_key = f"jwt_claims:{user_id}"
    cache.delete(cache_key)
    logger.info(f"Invalidated claims cache for user {user_id}")
```

## Best Practices

### 1. Keep Claims Minimal
- Only include essential information in JWT claims
- Large tokens can impact performance and may exceed header size limits
- Fetch detailed data from APIs as needed rather than storing everything in tokens

### 2. Handle Errors Gracefully
- Always use try-except blocks in your `get_custom_claims` method
- Return an empty dict `{}` on errors to prevent token generation failure
- Log errors for debugging but don't expose them to users

### 3. Consider Performance
- JWT tokens are generated on every login and token refresh
- Keep claims generation logic fast
- Use caching for expensive operations
- Avoid database queries when possible

### 4. Security Considerations
- Never include sensitive information (passwords, API keys, secrets)
- Be cautious with PII (Personally Identifiable Information)
- Remember that JWT tokens can be decoded by anyone (they're signed, not encrypted)
- Validate and sanitize any user-provided data before including in claims

### 5. Versioning and Compatibility
- Consider adding a claims version field for backward compatibility
- Handle missing attributes gracefully using `hasattr()` or `getattr()`
- Document your claims structure for API consumers

### 6. Testing
```python
# tests/test_jwt_claims.py
from django.test import TestCase
from django.contrib.auth import get_user_model
from myapp.jwt_claims import MyCustomClaimsProvider

User = get_user_model()


class TestCustomClaims(TestCase):
    def setUp(self):
        self.provider = MyCustomClaimsProvider()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass'
        )

    def test_get_custom_claims(self):
        claims = self.provider.get_custom_claims(self.user)
        self.assertIsInstance(claims, dict)
        # Add specific assertions for your claims

    def test_handles_none_user(self):
        claims = self.provider.get_custom_claims(None)
        self.assertEqual(claims, {})

    def test_handles_errors(self):
        # Test with an object that will cause an error
        class BadUser:
            def __getattr__(self, name):
                raise Exception("Error accessing attribute")

        claims = self.provider.get_custom_claims(BadUser())
        self.assertEqual(claims, {})
```

## Troubleshooting

### Claims Not Appearing in Token

1. **Check Registration**: Verify your provider is registered by checking logs for registration messages
2. **Check Method Name**: Ensure your method is named exactly `get_custom_claims` (not `get_claims`)
3. **Check User Object**: Verify the user object is being passed correctly
4. **Enable Debug Logging**:
   ```python
   import logging
   logging.getLogger('blockauth').setLevel(logging.DEBUG)
   ```

### Token Size Issues

If your tokens are too large:
1. Remove non-essential claims
2. Use shorter claim names
3. Store detailed data server-side and use reference IDs
4. Consider using separate tokens for different purposes

### Performance Issues

If token generation is slow:
1. Add caching for expensive operations
2. Avoid complex database queries
3. Pre-compute values when user data changes
4. Use async processing where appropriate

### Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| `AttributeError: 'NoneType' object has no attribute 'id'` | User object is None | Add null check at start of `get_custom_claims` |
| `ImportError: cannot import name 'jwt_manager'` | BlockAuth not installed | Ensure blockauth is in INSTALLED_APPS |
| Claims missing from token | Provider not registered | Register in Django app's `ready()` method |
| Token too large | Too many claims | Reduce claims, use caching, store details server-side |

## Advanced Topics

### Multiple Providers

You can register multiple claims providers for different parts of your application:

```python
# Register multiple providers
from auth_app.jwt_claims import register_auth_claims_provider
from billing.jwt_claims import register_billing_claims_provider
from analytics.jwt_claims import register_analytics_claims_provider

register_auth_claims_provider()
register_billing_claims_provider()
register_analytics_claims_provider()
```

### Conditional Claims

Add claims based on conditions:

```python
def get_custom_claims(self, user) -> Dict[str, Any]:
    claims = {}

    # Only add admin claims for staff users
    if user.is_staff:
        claims['admin_level'] = self._get_admin_level(user)
        claims['admin_permissions'] = self._get_admin_permissions(user)

    # Only add beta features for beta users
    if self._is_beta_user(user):
        claims['beta_features'] = True

    return claims
```

### Dynamic Claims Updates

Trigger claims updates when user data changes:

```python
# In your user update view or signal
from myapp.jwt_claims import invalidate_user_claims_cache

def user_role_changed_handler(sender, instance, **kwargs):
    """Handle user role changes"""
    invalidate_user_claims_cache(str(instance.id))
    # Optionally, you might want to revoke existing tokens
    # or force re-authentication
```

## Conclusion

The BlockAuth JWT claims provider system offers a flexible and powerful way to customize JWT tokens for your application's specific needs. By following the patterns and best practices outlined in this guide, you can create maintainable and performant custom claims providers that enhance your authentication system.

For more information, see:
- [BlockAuth Documentation](../README.md)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [Django Authentication](https://docs.djangoproject.com/en/stable/topics/auth/)