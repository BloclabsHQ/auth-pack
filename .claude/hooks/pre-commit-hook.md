# BlockAuth Pre-Commit Hook

## 🔐 MANDATORY SECURITY ENFORCEMENT

**⚠️ CRITICAL: ALL commits MUST pass [security-enforcement-hook.md](security-enforcement-hook.md)**

Security violations will AUTOMATICALLY BLOCK commits. NO EXCEPTIONS.

## 🎯 **Purpose**

This hook runs before each commit to ensure code quality, security, and consistency in the BlockAuth package.

## 🔍 **Pre-Commit Checks**

### **Code Quality**
- **Python Syntax**: Check for syntax errors in all Python files
- **Import Validation**: Verify all imports are valid and organized
- **Type Hints**: Ensure type annotations in public methods
- **Docstring Coverage**: Check for missing docstrings
- **Code Formatting**: Verify Black formatting compliance

### **Security Checks**
- **Secret Detection**: Scan for hardcoded secrets, API keys, or tokens
- **Cryptographic Security**: Verify secure random usage
- **Password Handling**: Ensure passwords are never logged
- **SQL Injection**: Check for potential SQL injection vectors
- **JWT Security**: Validate JWT implementation patterns

### **Django-Specific**
- **Model Validation**: Check model definitions and fields
- **Serializer Security**: Verify input validation in serializers
- **View Permissions**: Ensure authentication/permission decorators
- **Migration Files**: Check for migration conflicts
- **Settings Security**: Verify no sensitive data in settings

### **BlockAuth Specific**
- **JWT Claims**: Validate claims provider implementation
- **KDF Logic**: Check key derivation security
- **Token Generation**: Verify cryptographically secure tokens
- **OAuth Integration**: Validate OAuth flow implementation
- **Web3 Authentication**: Check wallet signature verification

## 🛠️ **Automated Checks**

### **Linting & Formatting**
```bash
# Run black for code formatting
black --check blockauth/

# Run isort for import sorting
isort --check-only blockauth/

# Run flake8 for style guide
flake8 blockauth/ --max-line-length=120

# Run pylint for code quality
pylint blockauth/
```

### **Type Checking**
```bash
# Run mypy for type checking
mypy blockauth/ --ignore-missing-imports
```

### **Security Scanning**
```bash
# Run bandit for security issues
bandit -r blockauth/ -f json

# Check for hardcoded secrets
detect-secrets scan blockauth/

# Dependency vulnerability check
safety check --json
```

### **Django Checks**
```bash
# Run Django system checks
python manage.py check --deploy

# Check for missing migrations
python manage.py makemigrations --check --dry-run
```

### **Test Execution**
```bash
# Run core test suite
pytest blockauth/tests/ -v

# Run security-specific tests
pytest blockauth/tests/ -m security

# Check test coverage
pytest --cov=blockauth --cov-report=term-missing
```

## ✅ **Validation Checklist**

### **Authentication & Security**
- [ ] No hardcoded credentials or secrets
- [ ] Passwords are hashed with bcrypt (12+ rounds)
- [ ] All endpoints have proper authentication
- [ ] Rate limiting configured for auth endpoints
- [ ] CSRF protection enabled for state-changing operations

### **JWT Implementation**
- [ ] Tokens use secure random generation
- [ ] Refresh tokens have appropriate expiry
- [ ] Claims don't contain sensitive information
- [ ] Token validation is comprehensive
- [ ] Blacklist/revocation mechanism exists

### **KDF System**
- [ ] High iteration count (100,000+)
- [ ] Dual encryption implemented
- [ ] Secure key storage
- [ ] No key material in logs
- [ ] Key rotation supported

### **Code Quality**
- [ ] All public functions have docstrings
- [ ] Type hints on public interfaces
- [ ] No commented-out code
- [ ] Meaningful variable names
- [ ] DRY principle followed

### **Testing**
- [ ] New features have tests
- [ ] Security edge cases tested
- [ ] Integration tests for auth flows
- [ ] Mocked external dependencies
- [ ] Test coverage > 80%

## 🚨 **Critical Violations**

These violations will **block the commit**:

1. **Hardcoded secrets or API keys**
2. **Passwords logged or stored in plain text**
3. **SQL injection vulnerabilities**
4. **Missing authentication on protected endpoints**
5. **Syntax errors or import failures**
6. **Failing core security tests**
7. **JWT tokens without expiration**
8. **Weak cryptographic algorithms**

## 📋 **Pre-Commit Commands**

```bash
# Full pre-commit check
make pre-commit

# Quick security check
make security-check

# Format code automatically
make format

# Run all tests
make test

# Generate coverage report
make coverage
```

## 🔧 **Auto-Fix Options**

Some issues can be automatically fixed:

```bash
# Auto-format with black
black blockauth/

# Auto-sort imports
isort blockauth/

# Auto-fix basic linting issues
autopep8 --in-place --recursive blockauth/

# Update requirements for security
pip-audit --fix
```

## 📝 **Commit Message Format**

Ensure commit messages follow this format:
```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation change
- `style`: Code style change
- `refactor`: Code refactoring
- `test`: Test addition/modification
- `chore`: Build/tool changes
- `security`: Security improvement

Example:
```
feat(jwt): Add custom claims provider system

Implement pluggable JWT claims provider architecture
allowing applications to add custom data to tokens.

Closes #123
```

## 🔄 **Skip Hooks (Emergency Only)**

In emergency situations, hooks can be skipped:
```bash
# Skip pre-commit hooks (use sparingly)
git commit --no-verify -m "emergency: fix critical bug"
```

**Note**: Skipping hooks should be rare and followed by proper cleanup.

## 📊 **Metrics Tracking**

The pre-commit hook tracks:
- Lines of code changed
- Test coverage delta
- Security issue count
- Code quality score
- Documentation coverage

These metrics help maintain code quality over time.