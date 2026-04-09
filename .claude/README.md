# Claude Configuration for BlockAuth Package

## 🎯 **Purpose**

This `.claude` directory contains Claude-specific configuration files for the BlockAuth authentication package. These files provide context, guidelines, and automation for Claude when working with this authentication library.

## 📁 **Directory Structure**

```
.claude/
├── agents/                    # Claude agent configurations
│   ├── blockauth-assistant.md # Main authentication assistant
│   ├── blockauth-security.md  # Security specialist agent
│   └── blockauth-migration.md # Migration specialist agent
├── hooks/                     # Pre and post-commit hooks
│   ├── pre-commit-hook.md    # Pre-commit validation
│   ├── post-commit-hook.md   # Post-commit actions
│   └── doc-update-hook.md    # Documentation update hook
└── README.md                 # This file
```

## 🤖 **Agents**

### **blockauth-assistant.md**
The main agent for BlockAuth development:
- **Package Overview**: Understanding of BlockAuth's architecture
- **Authentication Flows**: JWT, OAuth, Web3, passwordless
- **KDF System**: Key derivation and blockchain integration
- **Custom Claims**: JWT claims provider system
- **Security Patterns**: Best practices and vulnerability prevention
- **API Design**: RESTful endpoints, serializers, views
- **Testing**: Unit tests, integration tests, security tests

### **blockauth-security.md**
Security-focused agent for vulnerability analysis:
- **Security Auditing**: Code review for vulnerabilities
- **Crypto Operations**: Key generation, encryption, hashing
- **Token Security**: JWT best practices, refresh patterns
- **Rate Limiting**: DDoS protection, throttling
- **Input Validation**: Sanitization, SQL injection prevention

### **blockauth-migration.md**
Database and schema migration specialist:
- **Django Migrations**: Schema evolution strategies
- **Data Migration**: User data transformation
- **Backward Compatibility**: Version management
- **Performance**: Migration optimization

## 🪝 **Hooks**

### **Pre-Commit Hook**
Validates code before commits:
- **Python Quality**: Syntax, imports, type hints
- **Security Scanning**: Secret detection, vulnerability check
- **Django Patterns**: Model validation, serializers
- **BlockAuth Specific**: JWT implementation, KDF logic

### **Post-Commit Hook**
Automated tasks after commits:
- **Test Execution**: Run test suite
- **Documentation**: Update API docs
- **Package Building**: Generate distribution files
- **Changelog**: Update version history

### **Documentation Update Hook**
Ensures documentation stays current:
- **API Documentation**: Update endpoint docs
- **Custom Claims Guide**: Sync with implementation
- **README Updates**: Feature list, examples
- **Migration Guides**: Version upgrade paths

## 🚀 **Usage**

### **For Claude Users**
These configurations are automatically loaded when Claude works with the BlockAuth package. They provide:
- Context-aware code suggestions
- Security-first development patterns
- Automated quality checks
- Documentation consistency

### **For Developers**
1. **Agent Selection**: Choose appropriate agent for your task
2. **Hook Compliance**: Ensure code passes pre-commit checks
3. **Documentation**: Keep docs updated with hooks
4. **Security**: Follow security guidelines in agents

## 📊 **Package Architecture**

```
blockauth/
├── models/           # User, session models
├── views/            # Authentication views
├── serializers/      # API serializers
├── utils/            # Token, crypto, KDF utilities
├── jwt/              # JWT manager and claims
├── middleware/       # Authentication middleware
├── permissions/      # Permission classes
├── triggers/         # Event triggers
└── tests/           # Comprehensive test suite
```

## 🔐 **Security Guidelines**

### **Critical Security Rules**
1. **Never log sensitive data** (passwords, tokens, keys)
2. **Always hash passwords** with bcrypt (12+ rounds)
3. **Validate all inputs** before processing
4. **Use secure random** for token generation
5. **Implement rate limiting** on all auth endpoints

### **KDF Security**
- **Dual encryption**: User password + platform key
- **High iterations**: 100,000+ for PBKDF2
- **Secure storage**: Encrypted private keys
- **Key rotation**: Support for key updates

## 🧪 **Testing Requirements**

### **Test Coverage Areas**
- **Authentication flows**: Login, logout, refresh
- **Token management**: Generation, validation, expiry
- **Security**: Injection, XSS, CSRF protection
- **KDF operations**: Key generation, encryption
- **OAuth flows**: Provider integration tests
- **Web3 auth**: Wallet signature verification

### **Running Tests**
```bash
# Run all tests
pytest

# Run specific test module
pytest blockauth/tests/test_jwt.py

# Run with coverage
pytest --cov=blockauth

# Run security tests only
pytest -m security
```

## 📚 **Documentation**

### **Key Documentation Files**
- `README.md`: Package overview and quick start
- `docs/CUSTOM_JWT_CLAIMS.md`: JWT claims provider guide
- `docs/KDF_SYSTEM.md`: Key derivation documentation
- `docs/API_REFERENCE.md`: Complete API documentation
- `docs/MIGRATION_GUIDE.md`: Version upgrade guide

### **Documentation Standards**
- **Code examples**: Working, tested examples
- **API docs**: Complete parameter descriptions
- **Security notes**: Highlight security implications
- **Version info**: Specify version requirements

## 🔄 **Continuous Improvement**

### **Feedback Loop**
1. **Issue tracking**: Monitor GitHub issues
2. **Security updates**: Regular dependency updates
3. **Performance**: Profile and optimize hot paths
4. **Documentation**: Keep current with changes

### **Version Management**
- **Semantic versioning**: Major.Minor.Patch
- **Changelog**: Detailed change documentation
- **Deprecation**: Clear deprecation warnings
- **Migration paths**: Smooth upgrade guides

## 💡 **Best Practices**

### **Development Patterns**
```python
# Good: Explicit, secure, documented
def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token."""
    return secrets.token_urlsafe(length)

# Bad: Predictable, insecure
def generate_token():
    return str(uuid7())  # Non-sortable, use secrets.token_urlsafe for tokens
```

### **Error Handling**
```python
# Good: Specific error handling
try:
    user = User.objects.get(email=email)
except User.DoesNotExist:
    logger.warning(f"Login attempt for non-existent user: {email}")
    raise AuthenticationFailed("Invalid credentials")

# Bad: Generic exception catching
try:
    user = User.objects.get(email=email)
except Exception:
    raise AuthenticationFailed("Error")
```

## 🆘 **Support & Resources**

### **Internal Resources**
- Package repository: `/services/auth-pack`
- Issue tracker: GitHub Issues
- Documentation: `/docs` directory
- Examples: `/blockauth-demo` directory

### **External Resources**
- Django documentation
- JWT.io for token debugging
- OWASP security guidelines
- Web3 authentication standards

---

**Note**: This configuration is specifically for the BlockAuth package. For service-specific configurations, see the respective service's `.claude` directory.