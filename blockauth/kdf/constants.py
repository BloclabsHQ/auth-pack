"""
Constants for Key Derivation Function (KDF) Module

This module defines constants used throughout the KDF system including
feature flags, configuration keys, and security parameters.
"""

from enum import Enum


class KDFFeatures:
    """Feature flags for KDF functionality"""
    
    # Core KDF features
    ENABLE_KDF = 'ENABLE_KDF'                    # Master switch for KDF
    DETERMINISTIC_KEYS = 'DETERMINISTIC_KEYS'    # Same input always produces same key
    PASSWORD_VERIFICATION = 'PASSWORD_VERIFICATION'  # Verify passwords via KDF
    
    # Security features
    KEY_ENCRYPTION = 'KEY_ENCRYPTION'            # Encrypt private keys at rest
    KEY_ROTATION = 'KEY_ROTATION'                # Enable key rotation
    AUDIT_LOGGING = 'AUDIT_LOGGING'              # Log all key operations
    
    # Advanced features
    MULTI_ALGORITHM = 'MULTI_ALGORITHM'          # Support multiple KDF algorithms
    CUSTOM_ITERATIONS = 'CUSTOM_ITERATIONS'       # Allow custom iteration counts
    EXPORT_KEYS = 'EXPORT_KEYS'                  # Allow users to export private keys
    
    @classmethod
    def all_features(cls):
        """Get all available KDF feature constants"""
        return [
            cls.ENABLE_KDF,
            cls.DETERMINISTIC_KEYS,
            cls.PASSWORD_VERIFICATION,
            cls.KEY_ENCRYPTION,
            cls.KEY_ROTATION,
            cls.AUDIT_LOGGING,
            cls.MULTI_ALGORITHM,
            cls.CUSTOM_ITERATIONS,
            cls.EXPORT_KEYS,
        ]


class KDFAlgorithms:
    """Supported key derivation algorithms with performance characteristics"""
    
    PBKDF2_SHA256 = 'pbkdf2_sha256'      # PBKDF2 with SHA-256 (default)
    PBKDF2_SHA512 = 'pbkdf2_sha512'      # PBKDF2 with SHA-512
    ARGON2ID = 'argon2id'                 # Argon2id (most secure)
    SCRYPT = 'scrypt'                     # Scrypt (memory-hard)
    
    # Algorithm performance data (simplified)
    ALGORITHM_DATA = {
        PBKDF2_SHA256: {
            'name': 'PBKDF2-SHA256',
            'time_ms': 5,                    # per 10K iterations
            'memory_mb': 1,                  # constant memory
            'gpu_resistant': False,
            'attack_resistance': 'Moderate'
        },
        PBKDF2_SHA512: {
            'name': 'PBKDF2-SHA512', 
            'time_ms': 8,                    # per 10K iterations
            'memory_mb': 1,                  # constant memory
            'gpu_resistant': False,
            'attack_resistance': 'Moderate'
        },
        ARGON2ID: {
            'name': 'Argon2id',
            'time_ms': 200,                  # per 10K iterations
            'memory_mb': 64,                 # configurable memory
            'gpu_resistant': True,
            'attack_resistance': 'High'
        },
        SCRYPT: {
            'name': 'Scrypt',
            'time_ms': 150,                  # per 10K iterations
            'memory_mb': 32,                 # configurable memory
            'gpu_resistant': True,
            'attack_resistance': 'High'
        }
    }
    
    @classmethod
    def all_algorithms(cls):
        """Get all supported algorithms"""
        return [
            cls.PBKDF2_SHA256,
            cls.PBKDF2_SHA512,
            cls.ARGON2ID,
            cls.SCRYPT,
        ]
    
    @classmethod
    def is_supported(cls, algorithm: str) -> bool:
        """Check if algorithm is supported"""
        return algorithm in cls.all_algorithms()
    
    @classmethod
    def get_algorithm_info(cls, algorithm: str) -> dict:
        """
        Get basic information about a specific algorithm
        
        Args:
            algorithm: Algorithm name (e.g., 'pbkdf2_sha256')
            
        Returns:
            dict: Algorithm information including performance data
        """
        if algorithm not in cls.ALGORITHM_DATA:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        return cls.ALGORITHM_DATA[algorithm]
    
    @classmethod
    def compare_algorithms(cls, algorithms: list = None) -> dict:
        """
        Compare performance characteristics of different algorithms
        
        Args:
            algorithms: List of algorithms to compare (default: all)
            
        Returns:
            dict: Comparison data for specified algorithms
        """
        if algorithms is None:
            algorithms = cls.all_algorithms()
        
        comparison = {}
        for algo in algorithms:
            if algo in cls.ALGORITHM_DATA:
                data = cls.ALGORITHM_DATA[algo]
                comparison[algo] = {
                    'name': data['name'],
                    'time_ms': data['time_ms'],
                    'memory_mb': data['memory_mb'],
                    'gpu_resistant': data['gpu_resistant'],
                    'attack_resistance': data['attack_resistance']
                }
        
        return comparison
    
    @classmethod
    def recommend_algorithm(cls, requirements: dict) -> str:
        """
        Recommend an algorithm based on requirements
        
        Args:
            requirements: Dict with keys like 'max_time_ms', 'max_memory_mb', 
                         'gpu_resistant', 'high_security', etc.
        
        Returns:
            str: Recommended algorithm name
        """
        max_time = requirements.get('max_time_ms', float('inf'))
        max_memory = requirements.get('max_memory_mb', float('inf'))
        gpu_resistant = requirements.get('gpu_resistant', False)
        high_security = requirements.get('high_security', False)
        
        # Filter algorithms based on requirements
        candidates = []
        
        for algo, data in cls.ALGORITHM_DATA.items():
            # Check time constraint
            if data['time_ms'] > max_time:
                continue
            
            # Check memory constraint
            if data['memory_mb'] > max_memory:
                continue
            
            # Check GPU resistance requirement
            if gpu_resistant and not data['gpu_resistant']:
                continue
            
            candidates.append((algo, data))
        
        if not candidates:
            # Fallback to most permissive option
            return cls.PBKDF2_SHA256
        
        # If high security required, prefer Argon2id
        if high_security:
            for algo, data in candidates:
                if algo == cls.ARGON2ID:
                    return algo
        
        # If GPU resistance required, prefer Argon2id or Scrypt
        if gpu_resistant:
            for algo, data in candidates:
                if algo in [cls.ARGON2ID, cls.SCRYPT]:
                    return algo
            # If no GPU-resistant candidates found, return None to indicate no suitable option
            return None
        
        # Default to fastest option
        fastest = min(candidates, key=lambda x: x[1]['time_ms'])
        return fastest[0]


class ConfigKeys:
    """Configuration keys for KDF settings"""
    
    # KDF algorithm configuration
    KDF_ALGORITHM = 'KDF_ALGORITHM'              # Default algorithm to use
    KDF_ITERATIONS = 'KDF_ITERATIONS'             # Default iteration count
    KDF_MASTER_SALT = 'KDF_MASTER_SALT'          # Platform master salt
    
    # Security configuration
    MASTER_ENCRYPTION_KEY = 'MASTER_ENCRYPTION_KEY'  # Master encryption key
    KEY_ROTATION_DAYS = 'KEY_ROTATION_DAYS'          # Days between key rotations
    MAX_FAILED_ATTEMPTS = 'MAX_FAILED_ATTEMPTS'      # Max failed password attempts
    
    # Performance configuration
    CACHE_DERIVED_KEYS = 'CACHE_DERIVED_KEYS'        # Cache derived keys (addresses only)
    CACHE_TTL_SECONDS = 'CACHE_TTL_SECONDS'          # Cache TTL in seconds


class SecurityConstants:
    """Security-related constants and thresholds"""
    
    # Salt requirements
    MIN_SALT_LENGTH = 32                    # Minimum salt length in characters
    MIN_SALT_BYTES = 16                     # Minimum salt length in bytes (for binary salts)
    
    # Key requirements
    MIN_PASSWORD_LENGTH = 8                 # Minimum password length
    MIN_ITERATIONS = 1000                   # Minimum KDF iterations
    
    # Encryption requirements
    AES_KEY_LENGTH = 32                     # AES-256 key length in bytes
    AES_NONCE_LENGTH = 12                   # AES-GCM nonce length in bytes
    AES_TAG_LENGTH = 16                     # AES-GCM tag length in bytes


class SecurityLevels:
    """
    Security level presets with detailed performance characteristics.
    
    Each security level is optimized for specific use cases with documented
    performance characteristics to help developers choose the right level.
    
    Performance metrics are based on typical hardware (2.5GHz CPU, 8GB RAM)
    and represent single-threaded key derivation times.
    """
    
    LOW = {
        'iterations': 10000,
        'algorithm': KDFAlgorithms.PBKDF2_SHA256,
        'description': 'Development/testing only',
        'performance': {
            'estimated_time_ms': 5,           # ~5ms per key derivation
            'memory_usage_mb': 1,             # ~1MB peak memory usage
            'cpu_intensive': False,           # Low CPU usage
            'recommended_for': [
                'Development environments',
                'Unit testing',
                'CI/CD pipelines',
                'Local development'
            ],
            'security_rating': 'Basic',
            'attack_resistance': 'Low - vulnerable to brute force',
            'use_cases': 'Non-production, testing only'
        }
    }
    
    MEDIUM = {
        'iterations': 100000,
        'algorithm': KDFAlgorithms.PBKDF2_SHA256,
        'description': 'Standard production use',
        'performance': {
            'estimated_time_ms': 50,          # ~50ms per key derivation
            'memory_usage_mb': 1,             # ~1MB peak memory usage
            'cpu_intensive': False,           # Moderate CPU usage
            'recommended_for': [
                'Web applications',
                'Mobile apps',
                'Standard business applications',
                'General production use'
            ],
            'security_rating': 'Good',
            'attack_resistance': 'Moderate - reasonable brute force protection',
            'use_cases': 'Most production applications'
        }
    }
    
    HIGH = {
        'iterations': 500000,
        'algorithm': KDFAlgorithms.ARGON2ID,
        'description': 'High security applications',
        'performance': {
            'estimated_time_ms': 200,         # ~200ms per key derivation
            'memory_usage_mb': 64,            # ~64MB peak memory usage (Argon2)
            'cpu_intensive': True,            # High CPU usage
            'recommended_for': [
                'Enterprise applications',
                'Healthcare systems',
                'Government applications',
                'High-value data systems'
            ],
            'security_rating': 'High',
            'attack_resistance': 'High - resistant to ASIC/GPU attacks',
            'use_cases': 'Security-critical applications'
        }
    }
    
    CRITICAL = {
        'iterations': 1000000,
        'algorithm': KDFAlgorithms.ARGON2ID,
        'description': 'Financial/critical systems',
        'performance': {
            'estimated_time_ms': 500,         # ~500ms per key derivation
            'memory_usage_mb': 128,           # ~128MB peak memory usage (Argon2)
            'cpu_intensive': True,            # Very high CPU usage
            'recommended_for': [
                'Financial systems',
                'Cryptocurrency wallets',
                'Military/government systems',
                'Critical infrastructure'
            ],
            'security_rating': 'Maximum',
            'attack_resistance': 'Maximum - highly resistant to all attack types',
            'use_cases': 'Mission-critical, high-value systems'
        }
    }
    
    @classmethod
    def get_preset(cls, level: str) -> dict:
        """Get security preset configuration"""
        return getattr(cls, level.upper(), cls.MEDIUM)
    
    @classmethod
    def get_performance_summary(cls) -> dict:
        """
        Get a summary of all security levels with performance characteristics.
        
        Returns:
            dict: Performance summary for all security levels
        """
        return {
            'LOW': cls.LOW['performance'],
            'MEDIUM': cls.MEDIUM['performance'],
            'HIGH': cls.HIGH['performance'],
            'CRITICAL': cls.CRITICAL['performance']
        }
    
    @classmethod
    def recommend_level(cls, use_case: str, performance_requirements: dict = None) -> str:
        """
        Recommend a security level based on use case and performance requirements.
        
        Args:
            use_case: Description of the application use case
            performance_requirements: Dict with max_time_ms, max_memory_mb, etc.
            
        Returns:
            str: Recommended security level name
        """
        use_case_lower = use_case.lower()
        
        # Critical systems
        if any(keyword in use_case_lower for keyword in ['financial', 'banking', 'crypto', 'wallet', 'critical', 'military']):
            return 'CRITICAL'
        
        # High security systems
        if any(keyword in use_case_lower for keyword in ['enterprise', 'healthcare', 'government', 'security', 'sensitive']):
            return 'HIGH'
        
        # Development/testing
        if any(keyword in use_case_lower for keyword in ['development', 'testing', 'dev', 'test', 'local']):
            return 'LOW'
        
        # Default to medium for general production use
        return 'MEDIUM'


class ErrorMessages:
    """Standard error messages for KDF operations"""
    
    INVALID_ALGORITHM = "Unsupported key derivation algorithm"
    INVALID_ITERATIONS = "Invalid iteration count (must be > 1000)"
    INVALID_MASTER_SALT = "Master salt must be at least 32 characters"
    INVALID_ENCRYPTION_KEY = "Invalid encryption key format"
    KEY_DERIVATION_FAILED = "Failed to derive key from credentials"
    ENCRYPTION_FAILED = "Failed to encrypt private key"
    DECRYPTION_FAILED = "Failed to decrypt private key"
    INVALID_PASSWORD = "Invalid password for key verification"
    KEY_NOT_FOUND = "Private key not found for user"
    KEY_COMPROMISED = "Private key has been marked as compromised"
    RATE_LIMIT_EXCEEDED = "Too many key derivation attempts"
    INSUFFICIENT_ENTROPY = "Insufficient entropy in password"
