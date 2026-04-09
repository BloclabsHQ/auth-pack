# BlockAuth Documentation Update Hook

## 🎯 **Purpose**

This hook ensures that documentation stays synchronized with code changes in the BlockAuth package. It automatically updates documentation when relevant code changes are detected.

## 📚 **Documentation Areas**

### **API Documentation**
- **Endpoint Documentation**: REST API endpoints
- **Request/Response Schemas**: Serializer documentation
- **Authentication Methods**: Login, OAuth, Web3
- **Error Responses**: Error codes and messages
- **Rate Limiting**: Throttle configurations

### **Code Documentation**
- **Module Docstrings**: Package and module descriptions
- **Function Documentation**: Parameters, returns, examples
- **Class Documentation**: Attributes, methods, usage
- **Type Hints**: Comprehensive type annotations
- **Code Examples**: Working code snippets

### **User Guides**
- **Installation Guide**: Setup instructions
- **Quick Start**: Basic usage examples
- **Custom Claims Guide**: JWT customization
- **Migration Guide**: Version upgrade paths
- **Security Guide**: Best practices

### **Technical Documentation**
- **Architecture**: System design and flow
- **KDF System**: Key derivation documentation
- **Database Schema**: Model relationships
- **Configuration**: Settings and environment
- **Testing Guide**: Test execution and coverage

## 🔍 **Trigger Conditions**

Documentation updates are triggered when:

### **Code Changes**
```python
TRIGGER_PATTERNS = {
    "views/*.py": ["API_REFERENCE.md", "USER_GUIDE.md"],
    "serializers/*.py": ["API_REFERENCE.md", "SCHEMAS.md"],
    "models/*.py": ["DATABASE_SCHEMA.md", "MIGRATION_GUIDE.md"],
    "jwt/*.py": ["CUSTOM_JWT_CLAIMS.md", "JWT_GUIDE.md"],
    "utils/kdf.py": ["KDF_SYSTEM.md", "SECURITY_GUIDE.md"],
    "permissions/*.py": ["PERMISSIONS.md", "SECURITY_GUIDE.md"],
}
```

### **Configuration Changes**
- Settings file modifications
- Environment variable updates
- Requirements changes
- Docker configuration updates

### **Test Changes**
- New test cases added
- Test documentation needed
- Coverage requirements updated
- Performance benchmarks changed

## 📝 **Documentation Templates**

### **API Endpoint Template**
```markdown
## [Endpoint Name]

### Description
[Brief description of what the endpoint does]

### Request
- **Method**: [GET/POST/PUT/DELETE]
- **Path**: `/api/v1/[path]`
- **Authentication**: [Required/Optional]
- **Permissions**: [List required permissions]

### Parameters
| Name | Type | Required | Description |
|------|------|----------|-------------|
| [param] | [type] | [Yes/No] | [description] |

### Request Body
```json
{
  "field": "value"
}
```

### Response
```json
{
  "status": "success",
  "data": {}
}
```

### Error Responses
| Code | Message | Description |
|------|---------|-------------|
| 400 | Bad Request | [When this occurs] |
| 401 | Unauthorized | [When this occurs] |

### Example
```python
import requests

response = requests.post(
    "https://api.example.com/api/v1/[path]",
    json={"field": "value"},
    headers={"Authorization": "Bearer [token]"}
)
```
```

### **Custom Claims Provider Template**
```markdown
## [Provider Name]

### Purpose
[What this provider adds to JWT tokens]

### Implementation
```python
class [ProviderName]ClaimsProvider:
    def get_custom_claims(self, user):
        return {
            "claim_name": value,
        }
```

### Registration
```python
from blockauth.jwt.token_manager import jwt_manager
jwt_manager.register_claims_provider([ProviderName]ClaimsProvider())
```

### Token Structure
```json
{
  "user_id": "...",
  "claim_name": "value",
  "exp": 1234567890
}
```

### Usage Example
[Show how to use the claims in application]
```

## 🔄 **Auto-Update Process**

### **Step 1: Detect Changes**
```python
def detect_documentation_needs(changed_files):
    """Identify which docs need updating."""
    docs_to_update = set()

    for file in changed_files:
        for pattern, docs in TRIGGER_PATTERNS.items():
            if matches_pattern(file, pattern):
                docs_to_update.update(docs)

    return docs_to_update
```

### **Step 2: Extract Information**
```python
def extract_documentation_data(source_files):
    """Extract docstrings and metadata."""
    data = {
        "functions": extract_function_docs(source_files),
        "classes": extract_class_docs(source_files),
        "endpoints": extract_endpoint_docs(source_files),
        "models": extract_model_docs(source_files),
    }
    return data
```

### **Step 3: Update Documentation**
```python
def update_documentation(doc_file, extracted_data):
    """Update documentation with new information."""
    # Load existing documentation
    existing = load_documentation(doc_file)

    # Merge with new data
    updated = merge_documentation(existing, extracted_data)

    # Validate documentation
    if validate_documentation(updated):
        save_documentation(doc_file, updated)
    else:
        raise DocumentationError("Invalid documentation format")
```

### **Step 4: Validate Updates**
```python
def validate_documentation(doc_content):
    """Ensure documentation meets standards."""
    checks = [
        check_markdown_syntax,
        check_code_examples,
        check_links,
        check_completeness,
        check_consistency
    ]

    for check in checks:
        if not check(doc_content):
            return False

    return True
```

## ✅ **Documentation Checklist**

### **API Documentation**
- [ ] All endpoints documented
- [ ] Request/response examples provided
- [ ] Authentication requirements clear
- [ ] Error responses documented
- [ ] Rate limits specified

### **Code Documentation**
- [ ] All public functions have docstrings
- [ ] Parameters and returns documented
- [ ] Examples provided for complex functions
- [ ] Type hints complete
- [ ] Exceptions documented

### **User Guides**
- [ ] Installation steps current
- [ ] Quick start guide works
- [ ] Common use cases covered
- [ ] Troubleshooting section updated
- [ ] FAQ maintained

### **Technical Docs**
- [ ] Architecture diagrams current
- [ ] Database schema updated
- [ ] Configuration options listed
- [ ] Security considerations noted
- [ ] Performance tips included

## 🛠️ **Documentation Commands**

### **Generate Documentation**
```bash
# Generate API docs from code
sphinx-apidoc -o docs/api blockauth/

# Build HTML documentation
cd docs && make html

# Generate markdown API reference
pydoc-markdown -o docs/API_REFERENCE.md

# Extract docstrings to JSON
python scripts/extract_docstrings.py
```

### **Validate Documentation**
```bash
# Check markdown syntax
markdownlint docs/*.md

# Validate code examples
python scripts/validate_examples.py

# Check broken links
linkchecker docs/

# Spell check
aspell check docs/*.md
```

### **Preview Documentation**
```bash
# Start documentation server
mkdocs serve

# Open in browser
open http://localhost:8000

# Build static site
mkdocs build
```

## 📊 **Documentation Metrics**

### **Coverage Metrics**
```python
metrics = {
    "total_functions": count_functions(),
    "documented_functions": count_documented_functions(),
    "total_classes": count_classes(),
    "documented_classes": count_documented_classes(),
    "total_endpoints": count_endpoints(),
    "documented_endpoints": count_documented_endpoints(),
}

coverage = calculate_doc_coverage(metrics)
```

### **Quality Metrics**
```python
quality = {
    "readability_score": calculate_readability(),
    "example_coverage": count_examples() / count_functions(),
    "type_hint_coverage": count_type_hints() / count_parameters(),
    "link_validity": check_all_links(),
    "consistency_score": check_terminology_consistency(),
}
```

## 🚨 **Documentation Standards**

### **Required Elements**
1. **Purpose/Description**: Clear explanation of functionality
2. **Parameters**: All parameters documented with types
3. **Returns**: Return value and type specified
4. **Exceptions**: Possible exceptions listed
5. **Examples**: At least one working example
6. **Security Notes**: Any security considerations
7. **Version Info**: Version added/deprecated

### **Style Guide**
- Use present tense ("Returns" not "Will return")
- Be concise but complete
- Include code examples that can be copy-pasted
- Use consistent terminology
- Format with proper markdown

### **Code Example Standards**
```python
# Good: Complete, runnable example
"""
Example:
    >>> from blockauth.jwt import generate_token
    >>> token = generate_token(user_id="123")
    >>> print(token[:20])
    'eyJ0eXAiOiJKV1QiLCJh'
"""

# Bad: Incomplete example
"""
Example:
    generate_token(...)  # Returns token
"""
```

## 🔐 **Security Documentation**

Always document:
- Authentication requirements
- Permission levels needed
- Data validation performed
- Potential security risks
- Best practices for secure usage

## 📝 **Changelog Updates**

Automatically update CHANGELOG.md with:
- New features added
- Breaking changes
- Bug fixes
- Security updates
- Performance improvements
- Documentation updates

## 🎯 **Success Criteria**

Documentation update is complete when:
- [ ] All code changes reflected in docs
- [ ] Examples tested and working
- [ ] Links validated
- [ ] Spell check passed
- [ ] Format validated
- [ ] Reviewed by team

## 🔄 **Continuous Improvement**

- Track documentation metrics over time
- Gather user feedback on documentation
- Regular documentation audits
- Update based on common support questions
- Maintain documentation roadmap