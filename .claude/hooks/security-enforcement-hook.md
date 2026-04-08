# 🔐 SECURITY ENFORCEMENT HOOK - MANDATORY

## ⚠️ CRITICAL: This Hook BLOCKS ALL Insecure Code

**This hook AUTOMATICALLY REJECTS any code that violates security standards.**

---

## 🚨 AUTOMATIC SECURITY BLOCKS

### IMMEDIATE REJECTION Patterns

The following patterns will cause IMMEDIATE rejection of ANY commit:

#### 1. Hardcoded Secrets (INSTANT BLOCK)
```python
# ❌ BLOCKED PATTERNS
SECRET_KEY = "actual-secret-value"  # BLOCKED
API_KEY = "sk-1234567890"  # BLOCKED
PASSWORD = "hardcoded-pass"  # BLOCKED
PRIVATE_KEY = "0x1234..."  # BLOCKED
```

#### 2. Sensitive Data in Logs (INSTANT BLOCK)
```python
# ❌ BLOCKED PATTERNS
logger.info(f"Password: {password}")  # BLOCKED
print(f"Token: {token}")  # BLOCKED
logger.debug(f"Private key: {key}")  # BLOCKED
console.log(`Secret: ${secret}`)  # BLOCKED
```

#### 3. Weak Cryptography (INSTANT BLOCK)
```python
# ❌ BLOCKED PATTERNS
random.random()  # BLOCKED for tokens
uuid.uuid4()  # BLOCKED for security tokens
hashlib.md5()  # BLOCKED
hashlib.sha1()  # BLOCKED for security
bcrypt.gensalt(rounds=10)  # BLOCKED (< 14)
```

#### 4. SQL Injection Vulnerabilities (INSTANT BLOCK)
```python
# ❌ BLOCKED PATTERNS
f"SELECT * FROM users WHERE id = {user_id}"  # BLOCKED
"SELECT * FROM users WHERE email = '" + email + "'"  # BLOCKED
query = "DELETE FROM " + table_name  # BLOCKED
```

#### 5. Insufficient JWT Security (INSTANT BLOCK)
```python
# ❌ BLOCKED PATTERNS
jwt.decode(token, verify=False)  # BLOCKED
algorithms=['HS256', 'none']  # BLOCKED
ACCESS_TOKEN_LIFETIME = timedelta(hours=1)  # BLOCKED (> 15 min)
JWT_SECRET = "short-key"  # BLOCKED (< 32 chars)
```

---

## 🔍 AUTOMATED SECURITY SCANS

### Pre-Commit Security Checks

```bash
#!/bin/bash
# AUTOMATIC SECURITY ENFORCEMENT

# 1. Secret Detection
echo "🔍 Scanning for hardcoded secrets..."
detect-secrets scan --baseline .secrets.baseline || exit 1

# 2. Security Vulnerability Scan
echo "🔍 Scanning for security vulnerabilities..."
bandit -r . -ll -f json || exit 1

# 3. Dependency Vulnerability Check
echo "🔍 Checking dependencies for vulnerabilities..."
safety check --json || exit 1

# 4. Password Security Check
echo "🔍 Verifying password security..."
grep -r "bcrypt.gensalt" | grep -v "rounds=1[4-9]" && exit 1

# 5. JWT Security Check
echo "🔍 Verifying JWT security..."
grep -r "timedelta(minutes=" | grep -v "minutes=1[0-5])" && exit 1

# 6. Crypto Security Check
echo "🔍 Verifying cryptographic security..."
grep -r "random.random\|uuid.uuid4\|md5\|sha1" --include="*.py" && exit 1

# 7. SQL Injection Check
echo "🔍 Checking for SQL injection vulnerabilities..."
grep -r "f\"SELECT\|f\"INSERT\|f\"UPDATE\|f\"DELETE" --include="*.py" && exit 1

# 8. Private Key Check
echo "🔍 Checking for exposed private keys..."
grep -r "PRIVATE_KEY\|private_key" --include="*.py" | grep -v "encrypted" && exit 1

echo "✅ All security checks passed!"
```

---

## 🛡️ SECURITY VALIDATION RULES

### Password Security Validation
```python
def validate_password_security(code: str) -> bool:
    """MANDATORY password security validation."""

    # Check bcrypt rounds
    bcrypt_pattern = r'bcrypt\.gensalt\(rounds=(\d+)\)'
    matches = re.findall(bcrypt_pattern, code)
    for rounds in matches:
        if int(rounds) < 14:
            raise SecurityError(f"BLOCKED: bcrypt rounds {rounds} < 14")

    # Check PBKDF2 iterations
    pbkdf2_pattern = r'iterations=(\d+)'
    matches = re.findall(pbkdf2_pattern, code)
    for iterations in matches:
        if int(iterations) < 600_000:
            raise SecurityError(f"BLOCKED: PBKDF2 iterations {iterations} < 600,000")

    return True
```

### JWT Security Validation
```python
def validate_jwt_security(code: str) -> bool:
    """MANDATORY JWT security validation."""

    # Check token lifetime
    if 'ACCESS_TOKEN_LIFETIME' in code:
        if 'hours=' in code or 'days=' in code:
            raise SecurityError("BLOCKED: Access token lifetime > 15 minutes")

    # Check JWT secret length
    jwt_secret_pattern = r'JWT_SECRET[_KEY]*\s*=\s*["\'](.+?)["\']'
    matches = re.findall(jwt_secret_pattern, code)
    for secret in matches:
        if len(secret) < 32:
            raise SecurityError(f"BLOCKED: JWT secret too short ({len(secret)} < 32)")

    # Check for 'none' algorithm
    if "'none'" in code or '"none"' in code:
        if 'algorithms' in code:
            raise SecurityError("BLOCKED: 'none' algorithm not allowed")

    return True
```

### Web3 Security Validation
```python
def validate_web3_security(code: str) -> bool:
    """MANDATORY Web3 security validation."""

    # Check for plain private key storage
    if 'private_key' in code.lower():
        if 'encrypt' not in code and 'encrypted' not in code:
            raise SecurityError("BLOCKED: Private key not encrypted")

    # Check for zero address
    if '0x0000000000000000000000000000000000000000' in code:
        if 'raise' not in code and 'error' not in code:
            raise SecurityError("BLOCKED: Zero address not validated")

    return True
```

---

## 📊 SECURITY METRICS TRACKING

### Security Score Calculation
```python
def calculate_security_score(code: str) -> int:
    """Calculate security score (must be > 90)."""

    score = 100

    # Deduct points for security issues
    if 'TODO' in code and 'security' in code.lower():
        score -= 10  # Unresolved security TODOs

    if 'console.log' in code or 'print(' in code:
        score -= 5  # Debug statements

    if 'disable' in code and 'security' in code.lower():
        score -= 20  # Security features disabled

    if score < 90:
        raise SecurityError(f"BLOCKED: Security score {score} < 90")

    return score
```

---

## 🚫 FORBIDDEN PATTERNS

### Patterns That ALWAYS Block Commits

```python
FORBIDDEN_PATTERNS = [
    # Weak random
    r'random\.random\(\)',
    r'random\.randint\(',
    r'uuid\.uuid1\(',  # MAC address leak

    # Weak crypto
    r'md5\(',
    r'sha1\(',
    r'DES\(',
    r'RC4\(',

    # Eval/Exec
    r'eval\(',
    r'exec\(',
    r'compile\(',

    # Pickle with user data
    r'pickle\.loads\(',

    # OS command injection
    r'os\.system\(',
    r'subprocess\.call\(.*shell=True',

    # SQL injection
    r'f["\'](SELECT|INSERT|UPDATE|DELETE)',
    r'\.format\(.*(SELECT|INSERT|UPDATE|DELETE)',

    # Debug in production
    r'DEBUG\s*=\s*True',
    r'TEMPLATE_DEBUG\s*=\s*True',

    # Unvalidated redirect
    r'redirect\(request\.(GET|POST)\[',
]
```

---

## ⚡ EMERGENCY OVERRIDE

### Override Process (REQUIRES APPROVAL)

In EXTREME emergencies ONLY:

```bash
# EMERGENCY OVERRIDE (requires security team approval)
SECURITY_OVERRIDE_TOKEN="approved-by-security-team" git commit --no-verify

# This will:
# 1. Log the override with full context
# 2. Alert security team immediately
# 3. Create security review ticket
# 4. Require post-commit security audit
```

**WARNING**: Overrides are tracked and require written justification.

---

## 📝 SECURITY COMMIT MESSAGE

All security-related commits MUST use:

```
security: <type> - <description>

Security Impact:
- [Detail security implications]
- [List any new attack vectors]
- [Describe mitigations]

Testing:
- [Security tests added/modified]
- [Vulnerability scanning performed]

Compliance:
- [OWASP controls addressed]
- [Compliance requirements met]
```

---

## 🎯 ENFORCEMENT SUMMARY

This hook ENFORCES:

1. **NO hardcoded secrets** - Automatic rejection
2. **NO sensitive data in logs** - Automatic rejection
3. **NO weak cryptography** - Automatic rejection
4. **NO SQL injection risks** - Automatic rejection
5. **NO insufficient JWT security** - Automatic rejection
6. **NO plain private keys** - Automatic rejection
7. **NO debug mode in production** - Automatic rejection
8. **NO security score < 90** - Automatic rejection

**Remember**: Security is MANDATORY. This hook ensures it.