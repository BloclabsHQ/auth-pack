#!/usr/bin/env python3
"""
Example: Using Separate JWT Secret Key

This example shows how to configure and use a separate JWT secret key
instead of Django's default SECRET_KEY for token encoding/decoding.
"""

import os
from datetime import timedelta

# Example Django settings.py configuration
DJANGO_SETTINGS_EXAMPLE = """
# settings.py

# Django's main secret key (used for sessions, CSRF, etc.)
SECRET_KEY = 'django-secret-key-for-sessions-and-csrf'

# BlockAuth settings with separate JWT secret key
BLOCK_AUTH_SETTINGS = {
    # Use a different secret key specifically for JWT tokens
    "JWT_SECRET_KEY": "your-special-jwt-secret-key-here",
    
    # Other token settings
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_LIFETIME": timedelta(seconds=3600),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    
    # ... other settings
}
"""

# Example environment variables
ENV_VARS_EXAMPLE = """
# .env file
DJANGO_SECRET_KEY=django-secret-key-for-sessions-and-csrf
JWT_SECRET_KEY=your-special-jwt-secret-key-here
"""

# Example usage in settings.py with environment variables
SETTINGS_WITH_ENV_EXAMPLE = """
# settings.py
import os

SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')

BLOCK_AUTH_SETTINGS = {
    "JWT_SECRET_KEY": os.getenv('JWT_SECRET_KEY'),
    "ALGORITHM": "HS256",
    # ... other settings
}
"""

# Example for other services to decode tokens
OTHER_SERVICE_EXAMPLE = """
# Python example for other services
import jwt

# Use the same JWT secret key as configured in Django
JWT_SECRET_KEY = "your-special-jwt-secret-key-here"  # Must match Django JWT_SECRET_KEY
ALGORITHM = "HS256"

def decode_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")

# Usage
token = "your-jwt-token-here"
payload = decode_token(token)
user_id = payload['user_id']
token_type = payload['type']
"""

# Example Node.js service
NODEJS_EXAMPLE = """
// Node.js example for other services
const jwt = require('jsonwebtoken');

const JWT_SECRET_KEY = 'your-special-jwt-secret-key-here'; // Must match Django JWT_SECRET_KEY
const ALGORITHM = 'HS256';

function decodeToken(token) {
    try {
        const payload = jwt.verify(token, JWT_SECRET_KEY, { algorithms: [ALGORITHM] });
        return payload;
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            throw new Error('Token has expired');
        }
        throw new Error('Invalid token');
    }
}

// Usage
const token = 'your-jwt-token-here';
const payload = decodeToken(token);
const userId = payload.user_id;
const tokenType = payload.type;
"""

if __name__ == "__main__":
    print("=== JWT Secret Key Configuration Example ===\n")
    
    print("1. Django Settings Configuration:")
    print(DJANGO_SETTINGS_EXAMPLE)
    
    print("\n2. Environment Variables:")
    print(ENV_VARS_EXAMPLE)
    
    print("\n3. Settings with Environment Variables:")
    print(SETTINGS_WITH_ENV_EXAMPLE)
    
    print("\n4. Python Service Example:")
    print(OTHER_SERVICE_EXAMPLE)
    
    print("\n5. Node.js Service Example:")
    print(NODEJS_EXAMPLE)
    
    print("\n=== Key Points ===")
    print("- JWT_SECRET_KEY can be different from Django's SECRET_KEY")
    print("- All services must use the same JWT_SECRET_KEY to decode tokens")
    print("- Keep JWT_SECRET_KEY secure and use environment variables in production")
    print("- The JWT_SECRET_KEY falls back to Django's SECRET_KEY if not specified") 