# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BlockAuth is a Django REST Framework authentication package designed for internal use. It provides comprehensive authentication mechanisms including JWT tokens, social OAuth, Web3 wallet authentication, and OTP-based passwordless login. The package is distributed via Poetry and integrates with external microservices.

## Common Development Commands

### Package Management
- `poetry install` - Install dependencies (use for first-time setup)
- `poetry update` - Update dependencies to latest compatible versions
- `poetry add <package>` - Add new dependency
- `poetry build` - Build package for distribution

### Testing
- No specific test commands found in pyproject.toml - check with project team for test runner
- Test coverage should focus on authentication flows, token validation, and social auth integrations

### Installation Modes
- **Standard**: Add to pyproject.toml as `blockauth = { git = "git@github.com:BloclabsHQ/auth-pack.git", branch = "dev" }`
- **Editable**: Clone repo and `pip install -e <path-to-repo>` for active development

## Code Architecture

### Core Components

#### User Model (`blockauth/models/user.py`)
- `BlockUser` - Abstract base user model with UUID primary key, email, phone, wallet_address
- Supports multiple authentication types: EMAIL, WALLET, GOOGLE, FACEBOOK, LINKEDIN, PASSWORDLESS
- Uses JSONField for authentication_types list
- Includes helper methods: `add_authentication_type()`, `remove_authentication_type()`, `has_authentication_type()`

#### Authentication System (`blockauth/authentication.py`)
- `JWTAuthentication` - Custom DRF authentication class
- Validates Bearer tokens with configurable header names
- Integrates with `AUTH_TOKEN_CLASS` for token decoding
- Supports user lookup via configurable `USER_ID_FIELD`

#### URL Configuration (`blockauth/urls.py`)
- Dynamic URL generation based on feature flags in `BLOCK_AUTH_SETTINGS['FEATURES']`
- Feature-based endpoint control using `URL_PATTERN_MAPPINGS`
- Social auth URLs conditionally added based on provider configuration
- All endpoints use trailing slashes for consistency

#### Configuration System (`blockauth/utils/config.py`)
- Centralized config access via `get_config(key)`
- Dynamic user model resolution with `get_block_auth_user_model()`
- Social provider validation with `is_social_auth_configured(provider)`
- Handles optional settings gracefully

#### Constants (`blockauth/constants.py`)
- Type-safe constants for features, providers, config keys, URLs
- `Features` class - All available feature flags
- `SocialProviders` class - OAuth provider names  
- `URLNames` class - URL pattern names for reverse lookups
- `ConfigKeys` class - Valid configuration setting keys

### Key Patterns

#### Feature Flag System
- All functionality controlled by feature flags in `BLOCK_AUTH_SETTINGS['FEATURES']`
- Use `is_feature_enabled(Features.FEATURE_NAME)` to check availability
- URLs dynamically generated based on enabled features
- Social auth requires both `SOCIAL_AUTH` feature and provider configuration

#### Token Architecture
- JWT-based with separate access/refresh token lifetimes
- Configurable signing algorithm and secret key
- User verification status included in access tokens only
- Standard format: `{"user_id": "uuid-with-hyphens", "type": "access|refresh", "exp": timestamp, "iat": timestamp}`

#### Multi-Authentication Support
- Users can have multiple authentication methods simultaneously
- `authentication_types` JSONField tracks enabled methods per user
- Each auth type (EMAIL, WALLET, SOCIAL, etc.) managed independently
- Wallet authentication uses Web3 signature verification

### Integration Points

#### External Services
- **Subscription Service**: Plan validation and gas credits for account abstraction features
- **Notification Service**: OTP delivery and communication handling via `DEFAULT_NOTIFICATION_CLASS`
- **Bundler Services**: ERC-4337 UserOperation submission (account abstraction integration)
- **Social Providers**: Google, Facebook, LinkedIn OAuth2 flows

#### Database Dependencies
- Requires PostgreSQL with JSON field support
- User model must inherit from `BlockUser`
- OTP model for temporary code storage
- Migrations provided for core models

#### Configuration Requirements
- `BLOCK_AUTH_USER_MODEL` - Path to custom user model class
- `AUTH_PROVIDERS` - OAuth client credentials for social auth
- `FEATURES` - Feature flag dictionary enabling/disabling functionality
- Token lifetimes, OTP settings, rate limiting configuration

## Development Guidelines

### Adding New Features
1. Add feature flag to `Features` class in constants.py
2. Update `URL_PATTERN_MAPPINGS` in urls.py if adding endpoints
3. Create view classes following existing authentication patterns
4. Add comprehensive API documentation with drf-spectacular
5. Update feature dependencies if needed

### Authentication Flow Development
- All auth methods should support the trigger system (`PRE_SIGNUP_TRIGGER`, `POST_SIGNUP_TRIGGER`, `POST_LOGIN_TRIGGER`)
- Include proper logging with `BLOCK_AUTH_LOGGER_CLASS`
- Handle rate limiting using configured `REQUEST_LIMIT`
- Validate against feature flags before processing

### Social Provider Integration
- Provider configuration in `AUTH_PROVIDERS` with CLIENT_ID, CLIENT_SECRET, REDIRECT_URI
- OAuth flow: redirect to provider → callback with code → exchange for tokens → create/login user
- User data extraction and account linking via email
- Proper error handling for OAuth failures

### Web3 Integration
- Signature verification using eth-account library
- Support for MetaMask and other Web3 wallets
- Automatic user creation for new wallet addresses
- Optional email verification for wallet users

## Account Abstraction (Hybrid Web2/Web3 Approach)

BlockAuth implements Account Abstraction as an **additive layer** on top of existing Web2 authentication, ensuring seamless migration and backward compatibility.

### Design Principles

#### Web2 Foundation Consistency
- **Backward Compatibility**: All existing Web2 authentication methods (email/password, social OAuth, OTP) remain fully functional
- **Data Persistence**: User accounts, authentication history, and preferences are preserved during Web3 migration
- **Seamless Transition**: Users can upgrade from Web2 to Web3 without losing access or data
- **Dual Authentication**: Support both Web2 and Web3 authentication methods simultaneously on the same account
- **Progressive Enhancement**: Web3 features are opt-in enhancements, not replacements

#### Hybrid Architecture Benefits
- **User Choice**: Users can choose their preferred authentication method without forcing Web3 adoption
- **Gradual Migration**: Organizations can migrate users to Web3 progressively without disrupting existing workflows
- **Fallback Support**: Web2 authentication serves as fallback if Web3 services are unavailable
- **Compliance Continuity**: Existing audit trails and compliance processes remain intact
- **Risk Mitigation**: Reduced risk of user lockout or data loss during Web3 transition

### Current Status
- Planning phase with comprehensive TODO documentation in `docs/account_abstraction/`
- Smart contract development planned for Phase 1 (2-3 weeks)
- Python integration layer for Phase 2 (2-3 weeks)
- Full implementation involves 7 phases over ~3-4 months
- **CRITICAL**: All phases maintain Web2 authentication as primary system with Web3 as enhancement

### Hybrid Architecture Overview

#### Core Components
- **Existing Web2 System**: Unchanged JWT, OAuth, OTP authentication flows
- **Smart Account Extension**: Optional smart contract accounts linked to existing user accounts
- **Unified User Model**: Enhanced `BlockUser` with optional AA fields (smart_account_address, account_salt, etc.)
- **Authentication Router**: Intelligent routing between Web2 and Web3 authentication methods
- **Migration Service**: Seamless account upgrade from Web2 to Web3 with data preservation

#### Account Linking Strategy
```python
# Example: User account with both Web2 and Web3 capabilities
class HybridUser(BlockUser):
    # Existing Web2 fields (preserved)
    email = models.EmailField(...)
    password = models.CharField(...)
    authentication_types = models.JSONField(...)  # ['EMAIL', 'GOOGLE', 'WALLET']
    
    # Optional Web3 fields (additive)
    smart_account_address = models.CharField(null=True, blank=True)
    account_salt = models.CharField(null=True, blank=True)
    is_aa_enabled = models.BooleanField(default=False)
    preferred_auth_method = models.CharField(default='WEB2')  # 'WEB2', 'WEB3', 'HYBRID'
```

#### Migration Patterns
1. **Account Linking**: Link existing Web2 account to new smart contract account
2. **Data Migration**: Transfer user preferences, settings, and history to Web3-compatible format
3. **Authentication Bridging**: Support authentication via either Web2 or Web3 methods
4. **Progressive Upgrade**: Gradual feature migration (basic auth → smart accounts → advanced AA features)

### Development Approach

#### Mandatory Requirements
- **Web2 First**: All Web3 features must work alongside existing Web2 authentication
- **Zero Downtime Migration**: Account upgrades must not interrupt user access
- **Data Integrity**: All existing user data must be preserved and accessible post-migration
- **Fallback Mechanisms**: Web2 authentication must always be available as fallback
- **Audit Continuity**: Maintain consistent audit trails across Web2 and Web3 operations

#### Implementation Guidelines
When working on AA features, refer to detailed implementation guide in `docs/account_abstraction/ACCOUNT_ABSTRACTION_TODO.md` which includes:
- Hybrid architecture patterns maintaining Web2 compatibility
- Smart contract development standards with Web2 integration points
- Python integration patterns preserving existing authentication flows
- Migration strategies with zero-downtime requirements
- Security requirements for hybrid authentication systems
- Testing methodology for Web2/Web3 compatibility
- Performance benchmarks ensuring Web2 performance is not degraded

#### Feature Implementation Strategy
1. **Phase 1**: Extend existing models with optional AA fields
2. **Phase 2**: Implement parallel authentication systems (Web2 + Web3)
3. **Phase 3**: Add migration tools and user preference management
4. **Phase 4**: Implement advanced AA features while maintaining Web2 support
5. **Phase 5**: Optimize hybrid performance and add enterprise features
6. **Phase 6**: Advanced smart account features with Web2 fallback
7. **Phase 7**: Full production deployment with comprehensive monitoring

### User Experience Flow

#### New Users
- Default to Web2 authentication (email/password or social)
- Optional Web3 upgrade available in settings
- Progressive disclosure of Web3 features based on user engagement

#### Existing Users
- Maintain current authentication methods
- Optional migration to Web3 with guided onboarding
- Preserve all existing data, preferences, and access patterns
- Seamless transition with rollback capability

#### Enterprise Users
- Maintain existing SSO and compliance integrations
- Web3 features available as enterprise add-ons
- Centralized migration controls for administrator-managed rollouts
- Audit trail continuity for compliance requirements

## SOC2 Compliance & Enterprise Security Standards

### Security Requirements (MANDATORY)

#### Data Protection & Privacy
- **PII Protection**: Never log, display, or store sensitive user data (passwords, tokens, SSNs, payment info) in plain text
- **Data Encryption**: All sensitive data must be encrypted in transit (TLS 1.2+) and at rest (AES-256+)
- **Data Retention**: Implement data retention policies - automatically purge expired OTPs, old tokens, and temporary data
- **Data Classification**: Mark sensitive fields in models and APIs with appropriate security classifications
- **GDPR/CCPA Compliance**: Support data export, deletion, and consent management for user data

#### Access Controls & Authentication
- **Principle of Least Privilege**: Grant minimum required permissions for each user role and service
- **Multi-Factor Authentication**: Enforce MFA for admin accounts and sensitive operations
- **Session Management**: Implement secure session timeouts, token rotation, and concurrent session limits
- **Password Security**: Enforce strong password policies (12+ chars, complexity, no reuse of last 12 passwords)
- **Account Lockout**: Implement progressive lockout policies after failed authentication attempts

#### Audit & Logging Requirements
- **Audit Trail**: Log ALL authentication events, authorization decisions, and data access with immutable timestamps
- **Security Events**: Monitor and log failed logins, privilege escalations, configuration changes, and suspicious activities
- **Log Integrity**: Use centralized logging with tamper-proof storage and cryptographic log verification
- **Retention Policy**: Maintain audit logs for minimum 2 years with secure archival and retrieval processes
- **Real-time Monitoring**: Implement alerting for security violations and anomalous behavior patterns

#### Secure Development Practices
- **Code Review**: ALL security-related code requires mandatory peer review by security-trained developers
- **Static Analysis**: Run SAST tools (bandit, semgrep) on every commit to detect security vulnerabilities
- **Dependency Scanning**: Monitor and update dependencies for known CVEs using automated vulnerability scanning
- **Secrets Management**: Never commit secrets to repos - use secure vaults (HashiCorp Vault, AWS Secrets Manager)
- **Input Validation**: Sanitize and validate ALL user inputs to prevent injection attacks (SQL, XSS, LDAP, etc.)

### Implementation Guidelines

#### Secure Coding Standards
```python
# REQUIRED: Security decorators for sensitive operations
@require_audit_log(event_type="USER_AUTHENTICATION")
@rate_limit(max_attempts=5, window=300)  # 5 attempts per 5 minutes
@require_mfa_if_sensitive()
def authenticate_user(self, request):
    # Implementation must include audit logging
    pass

# REQUIRED: Input validation and sanitization
@validate_input(schema=UserRegistrationSchema)
@sanitize_output(remove_pii=True)
def create_user(self, validated_data):
    # Never log raw user input or PII
    pass
```

#### Configuration Security
- **Environment Separation**: Maintain strict separation between dev/staging/prod environments
- **Secure Defaults**: All security settings must default to most restrictive/secure values
- **Configuration Validation**: Validate security configurations on startup and alert on insecure settings
- **Key Management**: Rotate JWT signing keys regularly, use HSM for production key storage
- **API Security**: Implement API versioning, rate limiting, CORS policies, and request/response size limits

#### Database Security
- **Encryption at Rest**: Enable transparent data encryption for all database storage
- **Connection Security**: Use encrypted connections with certificate validation for all DB connections
- **Access Controls**: Implement database-level access controls with principle of least privilege
- **Data Masking**: Use data masking/tokenization for non-production environments
- **Backup Security**: Encrypt all database backups and restrict access to authorized personnel only

#### Incident Response
- **Security Playbook**: Document incident response procedures for authentication system breaches
- **Automated Response**: Implement automated threat detection and response for common attack patterns
- **Communication Plan**: Define escalation procedures and communication channels for security incidents
- **Forensic Readiness**: Maintain detailed logs and system state for post-incident forensic analysis

### Audit-Ready Practices

#### Documentation Requirements
- **Security Architecture**: Maintain current security architecture diagrams and threat models
- **Risk Assessments**: Document and update risk assessments for all authentication methods
- **Penetration Testing**: Conduct quarterly penetration testing with documented remediation plans
- **Compliance Mapping**: Map all security controls to relevant compliance frameworks (SOC2, ISO 27001, PCI-DSS)
- **Change Management**: Document all security-related changes with risk assessment and approval workflow

#### Monitoring & Metrics
- **Security Metrics**: Track and report on security KPIs (failed auth attempts, privilege escalations, etc.)
- **Compliance Reporting**: Generate automated compliance reports for audit purposes
- **Vulnerability Management**: Maintain vulnerability register with remediation tracking and SLA compliance
- **Third-Party Risk**: Assess and monitor security posture of all integrated third-party services

#### Operational Security
- **Secure Deployment**: Use infrastructure-as-code with security-hardened templates
- **Runtime Protection**: Implement RASP (Runtime Application Self-Protection) and WAF protection
- **Container Security**: Scan container images for vulnerabilities and use minimal base images
- **Network Security**: Implement network segmentation, firewall rules, and intrusion detection systems

### Code Review Security Checklist

Before any authentication-related code changes:
- [ ] No hardcoded secrets, credentials, or cryptographic keys
- [ ] All user inputs properly validated and sanitized
- [ ] Sensitive data properly encrypted and never logged
- [ ] Authentication failures logged with appropriate detail level
- [ ] Rate limiting implemented for all authentication endpoints
- [ ] Proper error handling without information disclosure
- [ ] Security headers configured (HSTS, CSP, X-Frame-Options, etc.)
- [ ] All database queries use parameterized statements
- [ ] Token expiration and revocation properly implemented
- [ ] Multi-tenant data isolation verified
- [ ] Audit logging captures all required security events
- [ ] Third-party integrations follow security standards

### Important Security Notes

- Package uses Poetry for dependency management, not pip/requirements.txt
- All endpoints include trailing slashes by Django convention  
- Feature flags are mandatory - no functionality works without proper configuration
- Social auth requires external OAuth app setup with providers
- User IDs in JWT tokens use standard UUID format with hyphens
- **CRITICAL**: Sensitive data automatically sanitized in logs - verify implementation
- Rate limiting applied per (identifier, subject, IP address) combination
- Package is currently in "initiative state" - ensure security reviews for all changes
- **MANDATORY**: All production deployments require security sign-off from InfoSec team
- **COMPLIANCE**: Maintain audit trail for all authentication events per SOC2 requirements