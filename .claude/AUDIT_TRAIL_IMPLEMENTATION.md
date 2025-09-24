# 📝 AUDIT TRAIL IMPLEMENTATION GUIDE

## ⚠️ MANDATORY: Complete Audit Trail for SOC2 & Enterprise Compliance

**EVERY action in the authentication system MUST be audited. NO EXCEPTIONS.**

---

## 🎯 AUDIT TRAIL REQUIREMENTS

### Mandatory Audit Events

```python
# MUST audit ALL of these events
MANDATORY_AUDIT_EVENTS = {
    # Authentication Events
    "auth.login.attempt": "User login attempted",
    "auth.login.success": "User login successful",
    "auth.login.failed": "User login failed",
    "auth.logout": "User logged out",
    "auth.session.created": "Session created",
    "auth.session.expired": "Session expired",
    "auth.session.revoked": "Session revoked",

    # Token Events
    "token.generated": "Token generated",
    "token.refreshed": "Token refreshed",
    "token.revoked": "Token revoked",
    "token.blacklisted": "Token blacklisted",
    "token.validation.failed": "Token validation failed",

    # Password Events
    "password.changed": "Password changed",
    "password.reset.requested": "Password reset requested",
    "password.reset.completed": "Password reset completed",
    "password.policy.violation": "Password policy violated",

    # MFA Events
    "mfa.enabled": "MFA enabled",
    "mfa.disabled": "MFA disabled",
    "mfa.challenged": "MFA challenge issued",
    "mfa.verified": "MFA verification successful",
    "mfa.failed": "MFA verification failed",

    # Account Events
    "account.created": "Account created",
    "account.updated": "Account updated",
    "account.deleted": "Account deleted",
    "account.locked": "Account locked",
    "account.unlocked": "Account unlocked",
    "account.suspended": "Account suspended",

    # Permission Events
    "permission.granted": "Permission granted",
    "permission.revoked": "Permission revoked",
    "permission.denied": "Permission denied",
    "role.assigned": "Role assigned",
    "role.removed": "Role removed",

    # Security Events
    "security.breach.detected": "Security breach detected",
    "security.threat.blocked": "Security threat blocked",
    "security.scan.completed": "Security scan completed",
    "rate.limit.exceeded": "Rate limit exceeded",
    "suspicious.activity": "Suspicious activity detected",

    # Web3 Events
    "wallet.connected": "Wallet connected",
    "wallet.disconnected": "Wallet disconnected",
    "signature.verified": "Signature verified",
    "signature.failed": "Signature verification failed",
    "transaction.signed": "Transaction signed",

    # Compliance Events
    "consent.granted": "User consent granted",
    "consent.withdrawn": "User consent withdrawn",
    "data.exported": "User data exported",
    "data.deleted": "User data deleted",
    "audit.accessed": "Audit log accessed",
}
```

---

## 🏗️ AUDIT TRAIL ARCHITECTURE

### Database Schema

```python
# MANDATORY: Audit trail database model
from django.db import models
from django.contrib.postgres.fields import JSONField
import uuid

class AuditLog(models.Model):
    """SOC2 compliant audit log model."""

    # Immutable fields (never update after creation)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    # Event identification
    event_type = models.CharField(max_length=100, db_index=True)
    event_description = models.TextField()
    severity = models.CharField(
        max_length=20,
        choices=[
            ('DEBUG', 'Debug'),
            ('INFO', 'Information'),
            ('WARNING', 'Warning'),
            ('ERROR', 'Error'),
            ('CRITICAL', 'Critical'),
        ],
        default='INFO',
        db_index=True
    )

    # User context
    user_id = models.UUIDField(null=True, blank=True, db_index=True)
    session_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField()

    # Request context
    request_id = models.UUIDField(db_index=True)
    request_method = models.CharField(max_length=10, null=True)
    request_path = models.CharField(max_length=255, null=True)
    request_data = JSONField(default=dict, blank=True)  # Sanitized data only

    # Response context
    response_status = models.IntegerField(null=True)
    response_time_ms = models.IntegerField(null=True)

    # Security context
    risk_score = models.IntegerField(default=0)
    threat_indicators = JSONField(default=list, blank=True)
    authentication_method = models.CharField(max_length=50, null=True)
    mfa_used = models.BooleanField(default=False)

    # Compliance context
    compliance_frameworks = JSONField(default=list)  # ['SOC2', 'ISO27001', 'GDPR']
    data_classification = models.CharField(
        max_length=20,
        choices=[
            ('PUBLIC', 'Public'),
            ('INTERNAL', 'Internal'),
            ('CONFIDENTIAL', 'Confidential'),
            ('RESTRICTED', 'Restricted'),
        ],
        default='INTERNAL'
    )

    # Integrity fields
    checksum = models.CharField(max_length=64, db_index=True)  # SHA-256 hash
    previous_checksum = models.CharField(max_length=64, null=True)  # Chain integrity

    # Metadata
    service_name = models.CharField(max_length=100, default='authentication')
    environment = models.CharField(max_length=20)  # 'production', 'staging', 'development'
    version = models.CharField(max_length=20)  # Application version

    class Meta:
        db_table = 'audit_trail'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'event_type']),
            models.Index(fields=['user_id', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['risk_score', 'timestamp']),
        ]

    def save(self, *args, **kwargs):
        """Ensure immutability and integrity."""
        if self.pk:  # Prevent updates
            raise ValueError("Audit logs are immutable and cannot be updated")

        # Calculate checksum
        self.checksum = self.calculate_checksum()

        super().save(*args, **kwargs)

    def calculate_checksum(self):
        """Calculate SHA-256 checksum for integrity."""
        import hashlib
        import json

        data = {
            'timestamp': str(self.timestamp),
            'event_type': self.event_type,
            'user_id': str(self.user_id),
            'ip_address': self.ip_address,
            'request_id': str(self.request_id),
            'response_status': self.response_status,
        }

        json_data = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_data.encode()).hexdigest()
```

---

## 🔍 AUDIT LOGGING IMPLEMENTATION

### Audit Logger Class

```python
# MANDATORY: Centralized audit logger
import logging
import json
from datetime import datetime
from typing import Any, Dict, Optional
import traceback

class AuditLogger:
    """SOC2 compliant audit logger."""

    def __init__(self):
        self.logger = logging.getLogger('audit')
        self.setup_handlers()

    def setup_handlers(self):
        """Setup multiple audit log handlers."""
        # Database handler
        db_handler = DatabaseAuditHandler()
        db_handler.setLevel(logging.INFO)

        # File handler (backup)
        file_handler = logging.FileHandler('/var/log/audit/authentication.log')
        file_handler.setLevel(logging.INFO)

        # SIEM handler (real-time)
        siem_handler = SIEMHandler()
        siem_handler.setLevel(logging.WARNING)

        # Add handlers
        self.logger.addHandler(db_handler)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(siem_handler)

    def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        severity: str = 'INFO',
        **kwargs
    ):
        """Log an audit event with full context."""

        # Get request context
        request = kwargs.get('request')
        if request:
            context = self.extract_request_context(request)
        else:
            context = {}

        # Build audit entry
        audit_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'event_description': MANDATORY_AUDIT_EVENTS.get(event_type, ''),
            'severity': severity,
            'user_id': user_id,
            'session_id': context.get('session_id'),
            'ip_address': context.get('ip_address'),
            'user_agent': context.get('user_agent'),
            'request_id': context.get('request_id'),
            'request_method': context.get('method'),
            'request_path': context.get('path'),
            'risk_score': self.calculate_risk_score(context),
            'compliance_frameworks': ['SOC2', 'ISO27001', 'GDPR'],
            **kwargs
        }

        # Store in database
        self.store_audit_entry(audit_entry)

        # Log to all handlers
        self.logger.info(json.dumps(audit_entry))

        # Real-time alerting for critical events
        if severity in ['ERROR', 'CRITICAL']:
            self.send_alert(audit_entry)

        return audit_entry

    def extract_request_context(self, request) -> Dict[str, Any]:
        """Extract context from HTTP request."""
        return {
            'session_id': getattr(request.session, 'session_key', None),
            'ip_address': self.get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'request_id': request.META.get('HTTP_X_REQUEST_ID', str(uuid.uuid4())),
            'method': request.method,
            'path': request.path,
        }

    def get_client_ip(self, request) -> str:
        """Get real client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    def calculate_risk_score(self, context: Dict) -> int:
        """Calculate risk score based on context."""
        risk_score = 0

        # IP reputation check
        if self.is_suspicious_ip(context.get('ip_address')):
            risk_score += 30

        # User agent analysis
        if self.is_suspicious_user_agent(context.get('user_agent')):
            risk_score += 20

        # Time-based analysis
        if self.is_unusual_time():
            risk_score += 10

        # Geographic analysis
        if self.is_unusual_location(context.get('ip_address')):
            risk_score += 25

        return min(risk_score, 100)  # Cap at 100

    def store_audit_entry(self, entry: Dict):
        """Store audit entry in database."""
        try:
            AuditLog.objects.create(**entry)
        except Exception as e:
            # Fallback to file logging if database fails
            self.logger.error(f"Failed to store audit entry: {e}")
            self.logger.info(f"FALLBACK: {json.dumps(entry)}")

# Global audit logger instance
audit_logger = AuditLogger()
```

---

## 🎨 AUDIT DECORATORS

### Function Decorator

```python
# MANDATORY: Audit decorator for all sensitive functions
from functools import wraps
import inspect

def audit_trail(
    event_type: str = None,
    severity: str = 'INFO',
    include_args: bool = False,
    include_result: bool = False
):
    """Decorator to automatically audit function calls."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Determine event type
            if event_type:
                audit_event_type = event_type
            else:
                audit_event_type = f"{func.__module__}.{func.__name__}"

            # Extract user context
            user_id = None
            request = None

            # Check for request in args
            for arg in args:
                if hasattr(arg, 'user'):
                    user_id = getattr(arg.user, 'id', None)
                    request = arg
                    break

            # Prepare audit data
            audit_data = {
                'function': func.__name__,
                'module': func.__module__,
            }

            # Include function arguments if requested
            if include_args:
                # Sanitize sensitive arguments
                safe_args = sanitize_arguments(func, args, kwargs)
                audit_data['arguments'] = safe_args

            # Log function call
            audit_logger.log_event(
                event_type=audit_event_type,
                user_id=user_id,
                severity=severity,
                request=request,
                action='function_called',
                **audit_data
            )

            try:
                # Execute function
                result = func(*args, **kwargs)

                # Log successful execution
                success_data = audit_data.copy()
                if include_result:
                    success_data['result'] = sanitize_result(result)

                audit_logger.log_event(
                    event_type=f"{audit_event_type}.success",
                    user_id=user_id,
                    severity='INFO',
                    request=request,
                    action='function_completed',
                    **success_data
                )

                return result

            except Exception as e:
                # Log failure
                audit_logger.log_event(
                    event_type=f"{audit_event_type}.failed",
                    user_id=user_id,
                    severity='ERROR',
                    request=request,
                    action='function_failed',
                    error=str(e),
                    traceback=traceback.format_exc(),
                    **audit_data
                )
                raise

        return wrapper
    return decorator

def sanitize_arguments(func, args, kwargs):
    """Remove sensitive data from arguments."""
    # Get function signature
    sig = inspect.signature(func)
    params = sig.parameters

    safe_args = {}
    sensitive_params = ['password', 'token', 'secret', 'key', 'private']

    # Process positional arguments
    for i, (param_name, param) in enumerate(params.items()):
        if i < len(args):
            if not any(s in param_name.lower() for s in sensitive_params):
                safe_args[param_name] = str(args[i])[:100]  # Truncate long values
            else:
                safe_args[param_name] = '[REDACTED]'

    # Process keyword arguments
    for key, value in kwargs.items():
        if not any(s in key.lower() for s in sensitive_params):
            safe_args[key] = str(value)[:100]
        else:
            safe_args[key] = '[REDACTED]'

    return safe_args

def sanitize_result(result):
    """Remove sensitive data from function result."""
    if isinstance(result, dict):
        return {k: '[REDACTED]' if 'token' in k.lower() or 'secret' in k.lower() else v
                for k, v in result.items()}
    return str(result)[:100]  # Truncate long results
```

---

## 🚦 DJANGO MIDDLEWARE FOR AUDIT

```python
# MANDATORY: Audit middleware for all requests
class AuditMiddleware:
    """Middleware to audit all HTTP requests."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Pre-request audit
        request_id = str(uuid.uuid4())
        request.META['HTTP_X_REQUEST_ID'] = request_id

        start_time = datetime.utcnow()

        # Log request
        audit_logger.log_event(
            event_type='http.request.received',
            user_id=getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
            severity='INFO',
            request=request,
            request_id=request_id,
        )

        try:
            # Process request
            response = self.get_response(request)

            # Calculate response time
            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            # Log response
            audit_logger.log_event(
                event_type='http.response.sent',
                user_id=getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                severity='INFO' if response.status_code < 400 else 'WARNING',
                request=request,
                request_id=request_id,
                response_status=response.status_code,
                response_time_ms=response_time,
            )

            return response

        except Exception as e:
            # Log error
            audit_logger.log_event(
                event_type='http.request.failed',
                user_id=getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                severity='ERROR',
                request=request,
                request_id=request_id,
                error=str(e),
                traceback=traceback.format_exc(),
            )
            raise
```

---

## 📊 AUDIT REPORTS & QUERIES

### Compliance Report Generation

```python
# MANDATORY: Generate compliance audit reports
class AuditReporter:
    """Generate audit reports for compliance."""

    @audit_trail(event_type='audit.report.generated')
    def generate_soc2_audit_report(self, start_date: datetime, end_date: datetime):
        """Generate SOC2 audit report."""

        report = {
            'report_type': 'SOC2 Type II',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
            },
            'generated_at': datetime.utcnow().isoformat(),
            'sections': {}
        }

        # Authentication events summary
        report['sections']['authentication'] = {
            'total_logins': self.count_events('auth.login.success', start_date, end_date),
            'failed_logins': self.count_events('auth.login.failed', start_date, end_date),
            'unique_users': self.count_unique_users(start_date, end_date),
            'mfa_usage': self.calculate_mfa_usage(start_date, end_date),
            'suspicious_activities': self.count_suspicious_activities(start_date, end_date),
        }

        # Security events summary
        report['sections']['security'] = {
            'security_incidents': self.count_security_incidents(start_date, end_date),
            'rate_limit_violations': self.count_events('rate.limit.exceeded', start_date, end_date),
            'permission_denials': self.count_events('permission.denied', start_date, end_date),
            'high_risk_events': self.count_high_risk_events(start_date, end_date),
        }

        # Compliance metrics
        report['sections']['compliance'] = {
            'audit_completeness': self.calculate_audit_completeness(start_date, end_date),
            'retention_compliance': self.verify_retention_compliance(),
            'data_integrity': self.verify_audit_integrity(start_date, end_date),
            'gdpr_requests': self.count_gdpr_requests(start_date, end_date),
        }

        # System availability
        report['sections']['availability'] = {
            'uptime_percentage': self.calculate_uptime(start_date, end_date),
            'average_response_time': self.calculate_avg_response_time(start_date, end_date),
            'error_rate': self.calculate_error_rate(start_date, end_date),
        }

        # Sign report
        report['signature'] = self.sign_report(report)

        return report

    def count_events(self, event_type: str, start_date: datetime, end_date: datetime) -> int:
        """Count events of specific type."""
        return AuditLog.objects.filter(
            event_type=event_type,
            timestamp__gte=start_date,
            timestamp__lte=end_date
        ).count()

    def verify_audit_integrity(self, start_date: datetime, end_date: datetime) -> bool:
        """Verify audit log integrity using checksums."""
        logs = AuditLog.objects.filter(
            timestamp__gte=start_date,
            timestamp__lte=end_date
        ).order_by('timestamp')

        for i, log in enumerate(logs):
            # Verify checksum
            if log.checksum != log.calculate_checksum():
                return False

            # Verify chain integrity (except first log)
            if i > 0 and log.previous_checksum != logs[i-1].checksum:
                return False

        return True
```

---

## 🔒 AUDIT LOG SECURITY

### Tamper-Proof Storage

```python
# MANDATORY: Ensure audit logs cannot be tampered with
class TamperProofAuditStorage:
    """Tamper-proof audit log storage."""

    def store(self, audit_entry: Dict):
        """Store audit entry with tamper protection."""

        # Add blockchain-style chaining
        previous_hash = self.get_last_hash()
        audit_entry['previous_hash'] = previous_hash

        # Calculate entry hash
        entry_hash = self.calculate_hash(audit_entry)
        audit_entry['hash'] = entry_hash

        # Store in multiple locations
        self.store_primary(audit_entry)  # Primary database
        self.store_backup(audit_entry)   # Backup database
        self.store_archive(audit_entry)  # Long-term archive

        # Send to immutable storage (e.g., write-once storage)
        self.store_immutable(audit_entry)

        return entry_hash

    def calculate_hash(self, entry: Dict) -> str:
        """Calculate cryptographic hash of entry."""
        import hashlib
        import json

        # Remove hash field if present
        entry_copy = entry.copy()
        entry_copy.pop('hash', None)

        # Sort keys for consistency
        json_str = json.dumps(entry_copy, sort_keys=True)

        # Calculate SHA-256 hash
        return hashlib.sha256(json_str.encode()).hexdigest()

    def verify_integrity(self, entry: Dict) -> bool:
        """Verify entry hasn't been tampered with."""
        stored_hash = entry.get('hash')
        calculated_hash = self.calculate_hash(entry)
        return stored_hash == calculated_hash
```

---

## 📈 AUDIT METRICS & MONITORING

```python
# MANDATORY: Real-time audit monitoring
class AuditMonitor:
    """Monitor audit logs for anomalies and compliance."""

    @continuous_monitor(interval=60)  # Every minute
    def monitor_audit_health(self):
        """Monitor audit system health."""

        metrics = {
            'audit_rate': self.calculate_audit_rate(),
            'error_rate': self.calculate_error_rate(),
            'high_risk_events': self.count_high_risk_events(),
            'missing_audits': self.detect_missing_audits(),
            'integrity_violations': self.check_integrity_violations(),
        }

        # Alert on anomalies
        if metrics['error_rate'] > 0.05:  # > 5% error rate
            self.alert('High error rate detected', metrics)

        if metrics['high_risk_events'] > 10:
            self.alert('Multiple high-risk events', metrics)

        if metrics['missing_audits'] > 0:
            self.alert('Missing audit entries detected', metrics)

        if metrics['integrity_violations'] > 0:
            self.alert('CRITICAL: Audit integrity violation', metrics)

        return metrics

    def detect_missing_audits(self) -> int:
        """Detect gaps in audit trail."""
        # Check for missing request IDs
        # Check for gaps in timestamps
        # Check for missing mandatory events
        pass
```

---

## 🎯 IMPLEMENTATION CHECKLIST

### Audit Trail Implementation Requirements

- [ ] Database schema created with all required fields
- [ ] Audit logger class implemented
- [ ] All mandatory events being logged
- [ ] Audit decorator applied to sensitive functions
- [ ] Middleware capturing all HTTP requests
- [ ] Tamper-proof storage implemented
- [ ] Integrity verification working
- [ ] Retention policies configured
- [ ] Real-time monitoring active
- [ ] SIEM integration complete
- [ ] Compliance reports generating
- [ ] Backup and archive storage configured
- [ ] Alert system operational
- [ ] Performance impact < 5%
- [ ] Audit logs encrypted at rest

---

## 📝 TESTING AUDIT TRAIL

```python
# MANDATORY: Test audit trail completeness
@pytest.mark.audit
class TestAuditTrail:
    """Test audit trail implementation."""

    def test_all_events_logged(self):
        """Verify all mandatory events are logged."""
        for event_type in MANDATORY_AUDIT_EVENTS.keys():
            assert AuditLog.objects.filter(event_type=event_type).exists()

    def test_audit_immutability(self):
        """Verify audit logs cannot be modified."""
        log = AuditLog.objects.create(
            event_type='test.event',
            ip_address='127.0.0.1'
        )

        with pytest.raises(ValueError):
            log.event_type = 'modified'
            log.save()

    def test_integrity_verification(self):
        """Verify integrity checking works."""
        log = AuditLog.objects.create(
            event_type='test.event',
            ip_address='127.0.0.1'
        )

        assert log.checksum == log.calculate_checksum()

    def test_retention_compliance(self):
        """Verify retention policies are enforced."""
        # Create old log
        old_log = AuditLog.objects.create(
            event_type='test.old',
            timestamp=datetime.utcnow() - timedelta(days=2556)
        )

        # Verify it's archived
        assert archive_storage.exists(old_log.id)
```

**Remember**: Complete audit trail is MANDATORY for compliance. Every action must be logged.