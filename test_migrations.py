#!/usr/bin/env python3
"""
Test script to verify BlockAuth migrations work correctly.
This script creates a minimal Django project and applies BlockAuth migrations.
"""

import os
import sys
import django
from django.conf import settings
from django.core.management import execute_from_command_line

# Configure Django settings for testing
if not settings.configured:
    settings.configure(
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
            }
        },
        INSTALLED_APPS=[
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'blockauth',
        ],
        AUTH_USER_MODEL='blockauth.BlockUser',
        SECRET_KEY='test-secret-key',
        USE_TZ=False,
    )
    django.setup()

def test_migrations():
    """Test that BlockAuth migrations can be applied successfully."""
    print("Testing BlockAuth migrations...")
    
    try:
        # Show current migration status
        print("\n1. Current migration status:")
        execute_from_command_line(['manage.py', 'showmigrations', 'blockauth'])
        
        # Apply migrations
        print("\n2. Applying migrations:")
        execute_from_command_line(['manage.py', 'migrate', 'blockauth'])
        
        # Show final migration status
        print("\n3. Final migration status:")
        execute_from_command_line(['manage.py', 'showmigrations', 'blockauth'])
        
        print("\n✅ All migrations applied successfully!")
        
    except Exception as e:
        print(f"\n❌ Migration test failed: {e}")
        return False
    
    return True

if __name__ == '__main__':
    success = test_migrations()
    sys.exit(0 if success else 1) 