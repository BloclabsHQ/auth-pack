"""
KDF Usage Examples

This file shows practical examples of how to use KDF functionality
in different scenarios and frameworks.
"""

# Example 1: Basic KDF Usage in Django
# In your Django views or services

def create_user_with_wallet(request):
    """Create a user with automatic wallet generation"""
    
    # Check if KDF is enabled
    from blockauth.kdf import is_enabled, get_kdf_service
    
    if not is_enabled():
        return JsonResponse({'error': 'KDF not enabled'}, status=400)
    
    try:
        # Get KDF service
        kdf_service = get_kdf_service()
        
        # Create wallet for user
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        wallet_data = kdf_service.create_user_wallet(email, password)
        
        # Store wallet data in your custom model
        from your_app.models import UserWallet
        UserWallet.objects.create(
            user=request.user,
            wallet_address=wallet_data['wallet_address'],
            salt=wallet_data['salt'],
            algorithm=wallet_data['algorithm'],
            iterations=wallet_data['iterations']
        )
        
        return JsonResponse({
            'success': True,
            'wallet_address': wallet_data['wallet_address']
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def verify_user_password(request):
    """Verify user password using KDF"""
    
    from blockauth.kdf import is_enabled, get_kdf_service
    
    if not is_enabled():
        return JsonResponse({'error': 'KDF not enabled'}, status=400)
    
    try:
        kdf_service = get_kdf_service()
        
        # Get stored wallet data
        from your_app.models import UserWallet
        user_wallet = UserWallet.objects.get(user=request.user)
        
        # Verify password
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        is_valid = kdf_service.verify_password(
            email, password, user_wallet.salt, user_wallet.wallet_address
        )
        
        if is_valid:
            return JsonResponse({'success': True, 'message': 'Password verified'})
        else:
            return JsonResponse({'error': 'Invalid password'}, status=401)
            
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Example 2: Using KDF Manager for Complete Wallet Management
# In your Django services

class WalletService:
    """Service for managing user wallets"""
    
    def __init__(self):
        from blockauth.kdf import is_enabled, get_kdf_manager
        
        if not is_enabled():
            raise ImportError("KDF not enabled")
        
        self.kdf_manager = get_kdf_manager()
    
    def create_wallet(self, email: str, password: str):
        """Create a complete wallet with encrypted storage"""
        
        # Create secure wallet
        wallet_data = self.kdf_manager.create_secure_wallet(email, password)
        
        # Store in your custom model
        from your_app.models import UserWallet
        return UserWallet.objects.create(
            email=email,
            wallet_address=wallet_data['wallet_address'],
            encrypted_private_key=wallet_data['encrypted_private_key'],
            salt=wallet_data['salt'],
            algorithm=wallet_data['algorithm'],
            iterations=wallet_data['iterations']
        )
    
    def get_private_key(self, email: str, password: str, user_wallet):
        """Get private key for transaction signing"""
        
        try:
            private_key = self.kdf_manager.verify_and_decrypt_key(
                email, password, user_wallet.salt, user_wallet.encrypted_private_key
            )
            return private_key
        except Exception as e:
            raise ValueError(f"Failed to get private key: {e}")


# Example 3: FastAPI Integration
# In your FastAPI application

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

class UserCreate(BaseModel):
    email: str
    password: str

class WalletResponse(BaseModel):
    wallet_address: str
    success: bool

@app.post("/create-wallet", response_model=WalletResponse)
async def create_wallet(user_data: UserCreate):
    """Create wallet for user"""
    
    try:
        # Check if KDF is enabled
        from blockauth.kdf import is_enabled, get_kdf_service
        
        if not is_enabled():
            raise HTTPException(status_code=400, detail="KDF not enabled")
        
        # Get KDF service
        kdf_service = get_kdf_service()
        
        # Create wallet
        wallet_data = kdf_service.create_user_wallet(
            user_data.email, user_data.password
        )
        
        # Store in your database (implement as needed)
        # await store_wallet_data(wallet_data)
        
        return WalletResponse(
            wallet_address=wallet_data['wallet_address'],
            success=True
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Example 4: Flask Integration
# In your Flask application

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/create-wallet', methods=['POST'])
def create_wallet():
    """Create wallet for user"""
    
    try:
        # Check if KDF is enabled
        from blockauth.kdf import is_enabled, get_kdf_service
        
        if not is_enabled():
            return jsonify({'error': 'KDF not enabled'}), 400
        
        # Get KDF service
        kdf_service = get_kdf_service()
        
        # Get request data
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        # Create wallet
        wallet_data = kdf_service.create_user_wallet(email, password)
        
        # Store in your database (implement as needed)
        # store_wallet_data(wallet_data)
        
        return jsonify({
            'success': True,
            'wallet_address': wallet_data['wallet_address']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Example 5: Custom User Model Integration
# In your Django models

from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    """Custom user model with wallet support"""
    
    # Add wallet-related fields
    wallet_address = models.CharField(max_length=42, blank=True, null=True)
    wallet_salt = models.CharField(max_length=64, blank=True, null=True)
    wallet_algorithm = models.CharField(max_length=20, blank=True, null=True)
    wallet_iterations = models.IntegerField(blank=True, null=True)
    
    def create_wallet(self, password: str):
        """Create wallet for this user"""
        
        from blockauth.kdf import is_enabled, get_kdf_service
        
        if not is_enabled():
            raise ImportError("KDF not enabled")
        
        kdf_service = get_kdf_service()
        
        # Create wallet
        wallet_data = kdf_service.create_user_wallet(self.email, password)
        
        # Update user fields
        self.wallet_address = wallet_data['wallet_address']
        self.wallet_salt = wallet_data['salt']
        self.wallet_algorithm = wallet_data['algorithm']
        self.wallet_iterations = wallet_data['iterations']
        self.save()
        
        return wallet_data
    
    def verify_password(self, password: str) -> bool:
        """Verify password using KDF"""
        
        if not self.wallet_address or not self.wallet_salt:
            return False
        
        from blockauth.kdf import is_enabled, get_kdf_service
        
        if not is_enabled():
            return False
        
        kdf_service = get_kdf_service()
        
        return kdf_service.verify_password(
            self.email, password, self.wallet_salt, self.wallet_address
        )


# Example 6: Transaction Signing Service
# In your blockchain services

class TransactionService:
    """Service for signing blockchain transactions"""
    
    def __init__(self):
        from blockauth.kdf import is_enabled, get_kdf_manager
        
        if not is_enabled():
            raise ImportError("KDF not enabled")
        
        self.kdf_manager = get_kdf_manager()
    
    def sign_transaction(self, user_wallet, email: str, password: str, 
                        transaction_data: dict):
        """Sign a transaction using user's private key"""
        
        try:
            # Get private key
            private_key = self.kdf_manager.verify_and_decrypt_key(
                email, password, user_wallet.salt, user_wallet.encrypted_private_key
            )
            
            # Sign transaction using web3
            from web3 import Web3
            from eth_account import Account
            
            account = Account.from_key(private_key)
            
            # Build and sign transaction
            signed_tx = account.sign_transaction(transaction_data)
            
            # Clear private key from memory
            private_key = '0' * len(private_key)
            del private_key
            
            return signed_tx.rawTransaction.hex()
            
        except Exception as e:
            raise ValueError(f"Failed to sign transaction: {e}")


# Example 7: Password Change with Wallet Preservation
# In your user management services

class PasswordChangeService:
    """Service for changing passwords while preserving wallets"""
    
    def __init__(self):
        from blockauth.kdf import is_enabled, get_kdf_manager
        
        if not is_enabled():
            raise ImportError("KDF not enabled")
        
        self.kdf_manager = get_kdf_manager()
    
    def change_password(self, user_wallet, old_password: str, 
                       new_password: str, email: str):
        """Change password while keeping the same wallet"""
        
        try:
            # First verify old password and get private key
            old_private_key = self.kdf_manager.verify_and_decrypt_key(
                email, old_password, user_wallet.salt, user_wallet.encrypted_private_key
            )
            
            # Generate new salt for new password
            import os
            new_salt = os.urandom(32).hex()
            
            # Re-encrypt with new password
            new_encrypted_data = self.kdf_manager.encryption_service.encrypt_private_key(
                old_private_key
            )
            
            # Update wallet data
            user_wallet.salt = new_salt
            user_wallet.encrypted_private_key = json.dumps(new_encrypted_data)
            user_wallet.save()
            
            # Clear private key from memory
            old_private_key = '0' * len(old_private_key)
            del old_private_key
            
            return True
            
        except Exception as e:
            raise ValueError(f"Failed to change password: {e}")


# Example 8: Batch Wallet Creation
# For bulk operations

def create_bulk_wallets(users_data: list):
    """Create wallets for multiple users"""
    
    from blockauth.kdf import is_enabled, get_kdf_service
    
    if not is_enabled():
        raise ImportError("KDF not enabled")
    
    kdf_service = get_kdf_service()
    results = []
    
    for user_data in users_data:
        try:
            wallet_data = kdf_service.create_user_wallet(
                user_data['email'], user_data['password']
            )
            
            results.append({
                'email': user_data['email'],
                'success': True,
                'wallet_address': wallet_data['wallet_address']
            })
            
        except Exception as e:
            results.append({
                'email': user_data['email'],
                'success': False,
                'error': str(e)
            })
    
    return results


# Example 9: Wallet Recovery/Export
# For allowing users to export their keys

def export_private_key(user_wallet, email: str, password: str):
    """Export private key for user (use with caution)"""
    
    from blockauth.kdf import is_enabled, get_kdf_manager
    
    if not is_enabled():
        raise ImportError("KDF not enabled")
    
    kdf_manager = get_kdf_manager()
    
    try:
        # Verify password and get private key
        private_key = kdf_manager.verify_and_decrypt_key(
            email, password, user_wallet.salt, user_wallet.encrypted_private_key
        )
        
        # Log this sensitive operation
        # log_key_export(user_wallet.user_id, request.ip_address)
        
        return private_key
        
    except Exception as e:
        raise ValueError(f"Failed to export private key: {e}")


# Example 10: Testing KDF Functionality
# In your test files

import unittest
from unittest.mock import patch

class TestKDFIntegration(unittest.TestCase):
    """Test KDF integration with your application"""
    
    def setUp(self):
        """Set up test environment"""
        # Mock Django settings
        with patch('django.conf.settings') as mock_settings:
            mock_settings.BLOCK_AUTH_SETTINGS = {
                'KDF_ENABLED': True,
                'KDF_ALGORITHM': 'pbkdf2_sha256',
                'KDF_ITERATIONS': 1000,  # Low for testing
                'KDF_MASTER_SALT': 'test-salt-32-chars-minimum',
                'MASTER_ENCRYPTION_KEY': '0x' + 'a' * 64,
            }
            
            from blockauth.kdf import get_kdf_service
            self.kdf_service = get_kdf_service()
    
    def test_wallet_creation(self):
        """Test wallet creation"""
        
        wallet_data = self.kdf_service.create_user_wallet(
            'test@example.com', 'TestPassword123'
        )
        
        self.assertIn('wallet_address', wallet_data)
        self.assertIn('salt', wallet_data)
        self.assertTrue(wallet_data['wallet_address'].startswith('0x'))
    
    def test_password_verification(self):
        """Test password verification"""
        
        wallet_data = self.kdf_service.create_user_wallet(
            'test@example.com', 'TestPassword123'
        )
        
        # Correct password
        is_valid = self.kdf_service.verify_password(
            'test@example.com', 'TestPassword123',
            wallet_data['salt'], wallet_data['wallet_address']
        )
        self.assertTrue(is_valid)
        
        # Wrong password
        is_valid = self.kdf_service.verify_password(
            'test@example.com', 'WrongPassword',
            wallet_data['salt'], wallet_data['wallet_address']
        )
        self.assertFalse(is_valid)


if __name__ == '__main__':
    # Run examples
    print("KDF Usage Examples")
    print("==================")
    print("This file contains examples of how to use KDF functionality.")
    print("Copy the relevant examples to your project.")
