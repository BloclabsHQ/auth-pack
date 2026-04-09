# BlockAuth Post-Commit Hook

## 🎯 **Purpose**

This hook runs after each successful commit to perform automated tasks, update documentation, and notify relevant systems about changes to the BlockAuth package.

## 🚀 **Post-Commit Actions**

### **Automated Testing**
- **Run Test Suite**: Execute comprehensive test suite
- **Generate Coverage Report**: Update code coverage metrics
- **Performance Benchmarks**: Run performance tests on critical paths
- **Security Audit**: Execute security test suite

### **Documentation Updates**
- **API Documentation**: Regenerate API docs from docstrings
- **Changelog Update**: Add commit to changelog
- **README Sync**: Update feature list and examples
- **Custom Claims Guide**: Sync with implementation changes

### **Package Management**
- **Version Bump**: Update version for releases
- **Build Package**: Generate distribution files
- **Dependency Check**: Verify dependency compatibility
- **License Headers**: Ensure license headers present

### **Notifications**
- **Team Notifications**: Alert team of significant changes
- **CI/CD Trigger**: Initiate build pipelines
- **Security Alerts**: Notify of security-related changes
- **Documentation Team**: Alert of API changes

## 📋 **Action Scripts**

### **Test Execution**
```bash
# Run full test suite
pytest blockauth/tests/ -v --tb=short

# Generate coverage report
pytest --cov=blockauth --cov-report=html --cov-report=term

# Run integration tests
pytest blockauth/tests/integration/ -v

# Execute performance benchmarks
pytest blockauth/tests/benchmarks/ --benchmark-only
```

### **Documentation Generation**
```bash
# Generate API documentation
sphinx-apidoc -o docs/api blockauth/

# Build HTML documentation
cd docs && make html

# Update changelog
git log --oneline --decorate > CHANGELOG_DRAFT.md

# Generate custom claims examples
python scripts/generate_claims_examples.py
```

### **Package Building**
```bash
# Clean previous builds
rm -rf build/ dist/ *.egg-info

# Build source distribution
python setup.py sdist

# Build wheel distribution
python setup.py bdist_wheel

# Verify package
twine check dist/*
```

### **Quality Metrics**
```bash
# Calculate code metrics
radon cc blockauth/ -a -nb

# Check maintainability index
radon mi blockauth/ -n B

# Generate complexity report
python -m mccabe --min 10 blockauth/
```

## 🔄 **Conditional Actions**

### **Based on Changed Files**

#### **If JWT files changed:**
```bash
# Regenerate JWT documentation
python scripts/update_jwt_docs.py

# Run JWT-specific tests
pytest blockauth/tests/test_jwt.py -v

# Update claims provider examples
python scripts/update_claims_examples.py
```

#### **If KDF files changed:**
```bash
# Run KDF security audit
python scripts/audit_kdf_security.py

# Execute KDF performance tests
pytest blockauth/tests/test_kdf_performance.py

# Update crypto documentation
python scripts/update_crypto_docs.py
```

#### **If OAuth files changed:**
```bash
# Test OAuth providers
pytest blockauth/tests/test_oauth_providers.py

# Validate OAuth configurations
python scripts/validate_oauth_config.py

# Update provider documentation
python scripts/update_oauth_docs.py
```

#### **If models changed:**
```bash
# Generate migrations
python manage.py makemigrations

# Check migration compatibility
python scripts/check_migration_compat.py

# Update model documentation
python scripts/update_model_docs.py
```

## 📊 **Metrics Collection**

### **Code Quality Metrics**
```python
metrics = {
    "total_lines": count_lines_of_code(),
    "test_coverage": get_test_coverage(),
    "cyclomatic_complexity": calculate_complexity(),
    "documentation_coverage": check_doc_coverage(),
    "security_score": run_security_audit(),
    "performance_score": run_benchmarks()
}

# Store metrics
save_metrics_to_database(metrics)
```

### **Change Impact Analysis**
```python
impact = {
    "files_changed": len(changed_files),
    "lines_added": count_additions(),
    "lines_removed": count_deletions(),
    "affected_modules": identify_affected_modules(),
    "breaking_changes": detect_breaking_changes(),
    "api_changes": detect_api_changes()
}

# Generate impact report
generate_impact_report(impact)
```

## 🔔 **Notifications**

### **Slack Notification**
```python
def notify_slack(commit_info):
    """Send commit notification to Slack."""
    message = {
        "text": f"BlockAuth Commit: {commit_info['message']}",
        "attachments": [{
            "color": "good",
            "fields": [
                {"title": "Author", "value": commit_info['author']},
                {"title": "Files", "value": commit_info['files_changed']},
                {"title": "Coverage", "value": commit_info['coverage']}
            ]
        }]
    }
    send_to_slack(message)
```

### **Email Notification**
```python
def notify_email(commit_info):
    """Send email for significant changes."""
    if commit_info['is_breaking_change']:
        send_email(
            to=TEAM_EMAIL,
            subject="Breaking Change in BlockAuth",
            body=format_breaking_change_email(commit_info)
        )
```

## 🛠️ **Maintenance Tasks**

### **Cleanup**
```bash
# Remove temporary files
find . -type f -name "*.pyc" -delete
find . -type d -name "__pycache__" -delete

# Clean test artifacts
rm -rf .pytest_cache/
rm -rf htmlcov/
rm -f .coverage

# Remove build artifacts
rm -rf build/ dist/ *.egg-info/
```

### **Dependency Updates**
```bash
# Check for outdated packages
pip list --outdated

# Update requirements
pip-compile --upgrade requirements.in

# Security audit dependencies
safety check --json

# License compliance check
pip-licenses --format=json
```

## 📈 **Performance Tracking**

### **Benchmark Results**
```python
def track_performance():
    """Track performance metrics over time."""
    benchmarks = run_performance_suite()

    # Compare with baseline
    baseline = load_baseline_metrics()
    regression = detect_regressions(benchmarks, baseline)

    if regression:
        alert_performance_regression(regression)

    # Update baseline if improved
    if benchmarks_improved(benchmarks, baseline):
        update_baseline(benchmarks)
```

## 🔐 **Security Audit**

### **Security Checks**
```bash
# Run security audit
bandit -r blockauth/ -f json -o security_report.json

# Check for known vulnerabilities
safety check --json --output vulnerabilities.json

# Scan for secrets
detect-secrets scan --baseline .secrets.baseline

# OWASP dependency check
dependency-check --scan blockauth/ --format JSON
```

## 📝 **Changelog Generation**

### **Auto-generate Changelog Entry**
```python
def update_changelog(commit):
    """Add commit to changelog."""
    entry = format_changelog_entry(commit)

    # Determine section based on commit type
    section = get_changelog_section(commit.type)

    # Add to appropriate section
    add_to_changelog(section, entry)

    # Generate release notes if version tag
    if is_version_tag(commit):
        generate_release_notes()
```

## 🎯 **Success Criteria**

Post-commit hook is successful when:
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Metrics are collected
- [ ] Notifications sent
- [ ] No security regressions
- [ ] Performance maintained

## 🚨 **Error Handling**

If post-commit actions fail:
1. Log error details
2. Send alert to team
3. Create issue ticket
4. Continue with remaining actions
5. Mark commit for review

## 📊 **Reporting**

Generate reports for:
- Test coverage trends
- Code quality metrics
- Performance benchmarks
- Security audit results
- Documentation coverage
- API changes

Reports are stored in `reports/` directory and sent to team dashboard.