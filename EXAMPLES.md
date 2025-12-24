# Real-World Usage Examples

This document provides practical examples of using Modular ReconX for various security testing scenarios.

## 📋 Table of Contents

- [Bug Bounty Hunting](#bug-bounty-hunting)
- [Penetration Testing](#penetration-testing)
- [Security Research](#security-research)
- [Incident Response](#incident-response)
- [Compliance & Auditing](#compliance-auditing)

---

## 🎯 Bug Bounty Hunting {#bug-bounty-hunting}

### Scenario 1: Initial Reconnaissance

**Goal**: Discover attack surface for a new bug bounty program

```bash
# Phase 1: Passive reconnaissance
reconx target.com --passive-only --correlate --output json

# Phase 2: Subdomain discovery via CT logs
reconx target.com --passive-only

# Phase 3: Cloud infrastructure enumeration
reconx target.com --cloud

# Phase 4: Technology stack identification
reconx target.com --bug-hunt
```

**What to look for:**

- Forgotten subdomains
- Public cloud storage buckets
- Outdated software versions
- Exposed admin panels

### Scenario 2: Cloud Misconfiguration Hunt

**Goal**: Find publicly accessible cloud storage

```bash
# Comprehensive cloud enumeration
reconx company.com --cloud

# Check specific subdomains
reconx dev.company.com --cloud
reconx staging.company.com --cloud
reconx backup.company.com --cloud
```

**Common findings:**

- Public S3 buckets with sensitive data
- Misconfigured Azure Blob containers
- Exposed GCP buckets
- Backup files in cloud storage

### Scenario 3: Metadata Intelligence

**Goal**: Extract sensitive information from public documents

```bash
# Find and analyze public documents
reconx target.com --metadata

# Combine with other recon
reconx target.com --metadata --social
```

**What you might discover:**

- Employee names and email patterns
- Internal software versions
- Network paths and server names
- Document creation dates (timeline)

### Scenario 4: Image Forensics Investigation

**Goal**: Find exposed sensitive data in images

```bash
# Analyze images on target domain
reconx target.com --forensics --reverse

# Local image analysis
reconx suspicious_image.jpg
```

**Potential findings:**

- GPS coordinates in photos
- Camera/device information
- Software used to create images
- Timestamps and metadata

---

## 🔒 Penetration Testing {#penetration-testing}

### Scenario 5: External Penetration Test

**Goal**: Comprehensive external assessment

```bash
# Full reconnaissance (with authorization)
reconx client.com --cloud --metadata --forensics --social --correlate --bug-hunt

# Use proxy for testing
reconx client.com --proxy http://127.0.0.1:8080 --rate-limit 0.5

# Passive-only for initial assessment
reconx client.com --passive-only --correlate
```

**Deliverables:**

- Complete asset inventory
- Technology stack analysis
- Potential vulnerabilities
- Cloud misconfigurations

### Scenario 6: Social Engineering Assessment

**Goal**: Gather intelligence for social engineering tests

```bash
# Generate dorks and analyze email patterns
reconx target.com --social

# Combine with metadata analysis
reconx target.com --social --metadata
```

**Use cases:**

- Phishing campaign preparation
- Pretexting scenarios
- Employee enumeration
- Email pattern discovery

---

## 🔬 Security Research {#security-research}

### Scenario 7: Vulnerability Research

**Goal**: Research specific vulnerability class

```bash
# Focus on WordPress sites
reconx wordpress-site.com --bug-hunt

# Check for specific misconfigurations
reconx target.com --cloud --metadata
```

**Research areas:**

- WordPress plugin vulnerabilities
- Cloud storage misconfigurations
- Metadata leakage patterns
- CORS misconfigurations

### Scenario 8: Comparative Analysis

**Goal**: Compare security posture of multiple domains

```bash
# Scan multiple targets
for domain in company1.com company2.com company3.com; do
    reconx $domain --cloud --metadata --output json
done

# Analyze results for patterns
```

**Analysis points:**

- Common misconfigurations
- Industry-specific issues
- Best practices adoption
- Security maturity levels

---

## 🚨 Incident Response {#incident-response}

### Scenario 9: Data Breach Investigation

**Goal**: Identify exposed data after a breach

```bash
# Check for exposed cloud storage
reconx compromised-company.com --cloud

# Analyze public documents for leaks
reconx compromised-company.com --metadata

# Check for exposed images with sensitive data
reconx compromised-company.com --forensics
```

**Investigation focus:**

- Publicly accessible backups
- Leaked credentials in metadata
- Exposed customer data
- Timeline reconstruction

### Scenario 10: Phishing Investigation

**Goal**: Investigate phishing campaign infrastructure

```bash
# Analyze phishing domain
reconx suspicious-domain.com --passive-only

# Check for related infrastructure
reconx suspicious-domain.com --correlate

# Analyze images used in phishing
reconx phishing-image.jpg
```

**Intelligence gathering:**

- Infrastructure fingerprinting
- Related domains
- Hosting provider information
- Image source tracking

---

## ✅ Compliance & Auditing {#compliance-auditing}

### Scenario 11: Cloud Security Audit

**Goal**: Verify cloud storage security

```bash
# Audit all company domains
reconx company.com --cloud
reconx *.company.com --cloud

# Check specific environments
reconx dev.company.com --cloud
reconx staging.company.com --cloud
reconx prod.company.com --cloud
```

**Compliance checks:**

- No public S3 buckets
- Proper access controls
- No exposed backups
- Secure configuration

### Scenario 12: Data Privacy Audit

**Goal**: Ensure GDPR/CCPA compliance

```bash
# Check for metadata leakage
reconx company.com --metadata

# Analyze images for PII
reconx company.com --forensics

# Check public documents
reconx company.com --metadata --forensics
```

**Privacy concerns:**

- PII in document metadata
- GPS coordinates in images
- Employee information exposure
- Sensitive data in public files

---

## 🎓 Advanced Techniques

### Scenario 13: Stealth Reconnaissance

**Goal**: Gather intelligence without detection

```bash
# Passive-only with rate limiting
reconx target.com --passive-only --rate-limit 2.0

# Use proxy for anonymity
reconx target.com --passive-only --proxy socks5://127.0.0.1:9050

# Custom user agent
reconx target.com --passive-only --user-agent "Mozilla/5.0..."
```

**Stealth tactics:**

- Passive-only scanning
- Rate limiting
- Proxy usage
- User agent rotation

### Scenario 14: Comprehensive Assessment

**Goal**: Complete security assessment

```bash
# Phase 1: Passive recon
reconx target.com --passive-only --correlate --output json

# Phase 2: Cloud & metadata
reconx target.com --cloud --metadata --output json

# Phase 3: Deep analysis
reconx target.com --forensics --social --reverse --bug-hunt --output json

# Phase 4: Focused testing
# Use findings from previous phases for manual testing
```

**Complete workflow:**

1. Passive reconnaissance
2. Cloud enumeration
3. Metadata analysis
4. Image forensics
5. Social engineering intel
6. Vulnerability scanning
7. Manual verification

---

## 💡 Pro Tips

### Combining Flags Effectively

```bash
# Maximum intelligence gathering
reconx target.com --cloud --metadata --forensics --social --reverse --correlate

# Stealth mode
reconx target.com --passive-only --rate-limit 1.5 --proxy http://proxy:8080

# Bug bounty focused
reconx target.com --cloud --metadata --bug-hunt --correlate

# Quick assessment
reconx target.com --passive-only --cloud
```

### Output Management

```bash
# JSON output for automation
reconx target.com --output json

# HTML report for clients
reconx target.com --output html

# CSV for spreadsheet analysis
reconx target.com --output csv
```

### Docker Usage

```bash
# Run in Docker for isolation
docker run --rm modular-reconx target.com --cloud --metadata

# With volume mapping for persistent results
docker run --rm -v $(pwd)/output:/app/output modular-reconx target.com --all

# Docker Compose for complex setups
docker-compose run --rm reconx target.com --bug-hunt
```

---

## ⚠️ Important Reminders

### Always Remember

1. ✅ **Get Authorization**: Never scan without permission
2. ✅ **Read Program Rules**: Understand scope and limitations
3. ✅ **Use Rate Limiting**: Be respectful of target infrastructure
4. ✅ **Document Everything**: Keep detailed logs
5. ✅ **Report Responsibly**: Follow proper disclosure procedures

### Common Mistakes to Avoid

- ❌ Scanning out-of-scope targets
- ❌ Aggressive scanning without rate limits
- ❌ Ignoring program rules
- ❌ Public disclosure before fixes
- ❌ Not documenting findings properly

---

## 📚 Additional Resources

### Learning More

- [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) - Ethical guidelines
- [SECURITY.md](SECURITY.md) - Security policy
- [TESTING.md](TESTING.md) - Test documentation
- [CHANGELOG.md](CHANGELOG.md) - Version history

### Community

- GitHub Issues: Report bugs and request features
- GitHub Discussions: Ask questions and share tips
- Bug Bounty Platforms: Practice on authorized targets

---

**Remember**: These examples are for authorized security testing only. Always obtain proper permission before scanning any target.

Happy (Ethical) Hacking! 🔐
