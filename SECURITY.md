# Security Policy

## 🔒 Reporting Security Vulnerabilities

We take the security of Modular ReconX seriously. If you discover a security vulnerability, we appreciate your help in disclosing it to us responsibly.

## 📧 How to Report

### Preferred Method

Please report security vulnerabilities by emailing:

- **Email**: Contact via GitHub Security Advisories (preferred)
- **Alternative**: Open a private security advisory on GitHub

### What to Include

Please provide:

1. **Description**: Clear description of the vulnerability
2. **Impact**: Potential impact and severity assessment
3. **Reproduction Steps**: Detailed steps to reproduce the issue
4. **Proof of Concept**: Code or screenshots demonstrating the vulnerability
5. **Suggested Fix**: If you have ideas for remediation
6. **Your Contact Info**: For follow-up questions

### Example Report Template

```text
**Vulnerability Type**: [e.g., Command Injection, Path Traversal]
**Affected Component**: [e.g., cloud_enum.py, scan.py]
**Severity**: [Critical/High/Medium/Low]

**Description**:
[Detailed description of the vulnerability]

**Steps to Reproduce**:
1. [First step]
2. [Second step]
3. [etc.]

**Impact**:
[What an attacker could achieve]

**Suggested Fix**:
[Your recommendations, if any]
```

## ⏱️ Response Timeline

We aim to:

- **Acknowledge** your report within **48 hours**
- **Provide an initial assessment** within **7 days**
- **Release a fix** within **90 days** (for critical issues, much sooner)
- **Publicly disclose** after a fix is available and deployed

## 🎯 Scope

### In Scope

Security vulnerabilities in:

- ✅ Core scanning modules (`app/modules/*.py`)
- ✅ Main execution script (`app/scan.py`)
- ✅ Docker configuration
- ✅ Dependency vulnerabilities
- ✅ Input validation issues
- ✅ Command injection vulnerabilities
- ✅ Path traversal issues
- ✅ Arbitrary code execution

### Out of Scope

The following are **not** considered security vulnerabilities:

- ❌ Issues in third-party dependencies (report to the upstream project)
- ❌ Social engineering attacks against users
- ❌ Denial of Service against external targets (this is a scanning tool)
- ❌ Issues requiring physical access to the user's machine
- ❌ Vulnerabilities in outdated versions (please update first)

## 🛡️ Security Best Practices for Users

### Safe Usage

1. **Keep Updated**: Always use the latest version
2. **Review Code**: Audit the code before running on sensitive systems
3. **Isolate Environment**: Run in Docker or virtual machines when possible
4. **Limit Permissions**: Don't run with unnecessary privileges
5. **Secure API Keys**: Store API keys in `.env`, never commit them

### Protecting Your Data

1. **Encrypt Results**: Scan results may contain sensitive information
2. **Secure Storage**: Store output files in encrypted directories
3. **Clean Up**: Delete scan results when no longer needed
4. **Access Control**: Restrict access to scan results

### Network Security

1. **Use VPN/Proxy**: When scanning sensitive targets
2. **Rate Limiting**: Use `--rate-limit` to avoid detection
3. **Passive Mode**: Use `--passive-only` for stealthy reconnaissance
4. **Monitor Traffic**: Be aware of what data is being sent

## 🔐 Known Security Considerations

### API Keys

- **Risk**: API keys in `.env` could be exposed if repository is made public
- **Mitigation**: `.env` is in `.gitignore` by default
- **User Action**: Never commit `.env` to version control

### Command Injection

- **Risk**: User input is passed to shell commands in some modules
- **Mitigation**: Input validation and sanitization implemented
- **User Action**: Only scan trusted domains

### Dependency Vulnerabilities

- **Risk**: Third-party libraries may have vulnerabilities
- **Mitigation**: Regular dependency updates
- **User Action**: Run `pip install --upgrade -r requirements.txt` regularly

### Data Exposure

- **Risk**: Scan results may contain sensitive information
- **Mitigation**: Results saved to local `output/` directory only
- **User Action**: Secure your `output/` directory appropriately

## 🏆 Security Hall of Fame

We recognize security researchers who help improve Modular ReconX:

<!-- Contributors who responsibly disclose vulnerabilities will be listed here -->

*No vulnerabilities reported yet. Be the first!*

## 📜 Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | ✅ Yes             |
| 1.1.x   | ✅ Yes             |
| < 1.1   | ❌ No              |

## 🔄 Security Update Process

When a security vulnerability is fixed:

1. **Patch Released**: Fix merged to main branch
2. **Version Bump**: New version released
3. **Security Advisory**: GitHub Security Advisory published
4. **Changelog Updated**: Details added to CHANGELOG.md
5. **Users Notified**: Via GitHub releases and notifications

## 📚 Additional Resources

### Security Tools

- [Bandit](https://github.com/PyCQA/bandit) - Python security linter
- [Safety](https://github.com/pyupio/safety) - Dependency vulnerability scanner
- [pip-audit](https://github.com/pypa/pip-audit) - Audit Python packages

### Security Guidelines

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)

## 🤝 Coordinated Disclosure

We follow **coordinated vulnerability disclosure** principles:

- We will work with you to understand and validate the issue
- We will keep you informed of our progress
- We will credit you in the security advisory (unless you prefer anonymity)
- We will not take legal action against good-faith security researchers

## ⚖️ Legal Safe Harbor

We support security research conducted in good faith:

- We will not pursue legal action for good-faith security research
- We will not report you to law enforcement for responsible disclosure
- We will work with you to understand the scope and impact

**Requirements for safe harbor protection:**

- Report vulnerabilities promptly and privately
- Do not access or modify user data beyond what's necessary to demonstrate the vulnerability
- Do not publicly disclose the vulnerability before we've had a chance to fix it
- Act in good faith and avoid privacy violations, data destruction, or service disruption

## 📞 Contact

For security-related questions that are not vulnerabilities:

- GitHub Discussions: Tag with `security`
- General inquiries: See README.md for contact information

---

**Thank you for helping keep Modular ReconX and its users safe!** 🙏
