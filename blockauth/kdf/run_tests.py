#!/usr/bin/env python3
"""
Simple test runner for KDF module

This script runs basic tests to verify the KDF module is working correctly.
Run this to test your KDF installation.
"""

import sys
import os

# Add the parent directory to the path so we can import blockauth
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

def test_kdf_imports():
    """Test that KDF can be imported correctly"""
    print("Testing KDF imports...")
    
    try:
        from blockauth.kdf import is_enabled, KDFFeatures
        print("✅ KDF module imported successfully")
        print(f"✅ Available features: {KDFFeatures.all_features()}")
        return True
    except ImportError as e:
        print(f"❌ Failed to import KDF module: {e}")
        return False

def test_kdf_disabled_by_default():
    """Test that KDF is disabled by default"""
    print("\nTesting KDF disabled by default...")
    
    try:
        from blockauth.kdf import is_enabled
        
        # Should be disabled by default
        if not is_enabled():
            print("✅ KDF correctly disabled by default")
            return True
        else:
            print("❌ KDF should be disabled by default")
            return False
    except Exception as e:
        print(f"❌ Error testing KDF disabled state: {e}")
        return False

def test_kdf_enabled_with_settings():
    """Test that KDF can be enabled with settings"""
    print("\nTesting KDF enabled with settings...")
    
    try:
        # Mock Django settings
        from unittest.mock import patch
        
        with patch('django.conf.settings') as mock_settings:
            mock_settings.BLOCK_AUTH_SETTINGS = {
                'KDF_ENABLED': True,
                'KDF_ALGORITHM': 'pbkdf2_sha256',
                'KDF_ITERATIONS': 1000,
                'KDF_MASTER_SALT': 'test-salt-32-chars-minimum',
                'MASTER_ENCRYPTION_KEY': '0x' + 'a' * 64,
            }
            
            from blockauth.kdf import is_enabled, get_kdf_service
            
            if is_enabled():
                print("✅ KDF correctly enabled with settings")
                
                # Test service creation
                kdf_service = get_kdf_service()
                print("✅ KDF service created successfully")
                
                # Test basic functionality
                wallet_data = kdf_service.create_user_wallet(
                    'test@example.com', 'TestPassword123'
                )
                
                if 'wallet_address' in wallet_data:
                    print("✅ Wallet creation works correctly")
                    print(f"   Wallet address: {wallet_data['wallet_address'][:10]}...")
                    return True
                else:
                    print("❌ Wallet creation failed")
                    return False
            else:
                print("❌ KDF not enabled even with settings")
                return False
                
    except Exception as e:
        print(f"❌ Error testing KDF enabled state: {e}")
        return False

def test_kdf_environment_variables():
    """Test that KDF works with environment variables"""
    print("\nTesting KDF with environment variables...")
    
    try:
        # Set environment variables
        os.environ['KDF_ENABLED'] = 'true'
        os.environ['KDF_ALGORITHM'] = 'pbkdf2_sha256'
        os.environ['KDF_ITERATIONS'] = '1000'
        os.environ['KDF_MASTER_SALT'] = 'env-salt-32-chars-minimum'
        os.environ['MASTER_ENCRYPTION_KEY'] = '0x' + 'b' * 64
        
        from blockauth.kdf import is_enabled, get_kdf_service
        
        if is_enabled():
            print("✅ KDF enabled with environment variables")
            
            # Test service creation
            kdf_service = get_kdf_service()
            print("✅ KDF service created with environment variables")
            
            # Test basic functionality
            wallet_data = kdf_service.create_user_wallet(
                'envtest@example.com', 'EnvPassword123'
            )
            
            if 'wallet_address' in wallet_data:
                print("✅ Environment-based wallet creation works")
                print(f"   Wallet address: {wallet_data['wallet_address'][:10]}...")
                return True
            else:
                print("❌ Environment-based wallet creation failed")
                return False
        else:
            print("❌ KDF not enabled with environment variables")
            return False
            
    except Exception as e:
        print(f"❌ Error testing KDF with environment variables: {e}")
        return False
    finally:
        # Clean up environment variables
        for key in ['KDF_ENABLED', 'KDF_ALGORITHM', 'KDF_ITERATIONS', 
                   'KDF_MASTER_SALT', 'MASTER_ENCRYPTION_KEY']:
            if key in os.environ:
                del os.environ[key]

def main():
    """Run all tests"""
    print("🧪 KDF Module Test Runner")
    print("=" * 50)
    
    tests = [
        test_kdf_imports,
        test_kdf_disabled_by_default,
        test_kdf_enabled_with_settings,
        test_kdf_environment_variables,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! KDF module is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Check the output above for details.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
