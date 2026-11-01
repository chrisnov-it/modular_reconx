# Real-World Usage Examples

This document provides practical examples of using Modular ReconX for various security testing scenarios.

## 📋 Table of Contents

- [Quick Reference](#quick-reference)
- [Bug Bounty Hunting](#bug-bounty-hunting)
- [Penetration Testing](#penetration-testing)
- [Security Research](#security-research)
- [Incident Response](#incident-response)
- [Compliance & Auditing](#compliance-auditing)
- [Scan Profiles Guide](#scan-profiles-guide)

---

## ⚡ Quick Reference

```bash
# Fastest, least noisy scan (safe for sensitive networks)
reconx example.com --profile safe

# Passive only (no packets sent to target directly)
reconx example.com --profile passive

# Full bug bounty hunt (requires aggressive profile)
reconx example.com --profile aggressive --bug-hunt --output md

# Fast scan skipping slow port scans and path brute-force
reconx example.com --skip-ports --skip-bruteforce

# Inspect a local suspicious file (no domain needed)
reconx image.jpg
reconx document.pdf
```

---

## 🎯 Bug Bounty Hunting

### Scenario 1: Initial Reconnaissance

**Goal**: Discover attack surface for a new bug bounty program

```bash
# Phase 1: Pure passive reconnaissance (no alert triggers)
reconx target.com --profile passive --output json

# Phase 2: Correlate IP neighbors and subdomains
reconx target.com --profile passive --correlate --enhanced-subdomains

# Phase 3: Cloud infrastructure enumeration
reconx target.com --cloud

# Phase 4: Full bug-hunt (API, CORS, GraphQL, HPP)
# NOTE: --bug-hunt ALWAYS requires --profile aggressive
reconx target.com --profile aggressive --bug-hunt --output md
```

**What to look for:**
- Forgotten subdomains (`dev-api.target.com`, `admin-test.target.com`)
- Public cloud storage buckets (AWS S3, Azure Blob, GCP)
- Outdated software versions and exposed CVEs
- Leaked credentials or tokens in JavaScript/API endpoints

### Scenario 2: Cloud Misconfiguration Hunt

**Goal**: Find publicly accessible cloud storage buckets/containers

```bash
# Comprehensive cloud enumeration for main domain
reconx company.com --cloud

# Check specific subdomains and environments
reconx dev.company.com --cloud
reconx staging.company.com --cloud
reconx backup.company.com --cloud
```

**Common findings:**
- Public S3 buckets with read/write permissions
- Misconfigured Azure Blob containers hosting backup dumps
- GCP buckets exposing internal documents

### Scenario 3: Document Metadata Intelligence

**Goal**: Extract sensitive internal info from publicly indexed documents

```bash
# Find and analyze public documents (PDF, DOCX)
reconx target.com --metadata

# Combine document metadata with social engineering dorks
reconx target.com --metadata --social
```

**What you might discover:**
- Internal usernames, employee names, email naming patterns
- Software used to author documents (reveals OS/software patch levels)
- Internal network paths, printer paths, shared network drives

### Scenario 4: Image Forensics Investigation

**Goal**: Find exposed sensitive metadata or location data in images

```bash
# Analyze images on target domain and generate reverse search links
reconx target.com --forensics --reverse

# Local image analysis (no domain scan needed)
reconx suspicious_image.jpg
```

**Potential findings:**
- GPS latitude/longitude embedded in uploaded photos (EXIF)
- Camera device info, lens, original timestamps
- Image alteration software signatures (Photoshop, GIMP)

---

## 🔒 Penetration Testing

### Scenario 5: External Penetration Test (Authorized)

**Goal**: Full scope reconnaissance for formal pen test engagement

```bash
# Full reconnaissance with throttling to avoid IPS block
reconx client.com --profile aggressive --bug-hunt \
  --cloud --metadata --forensics --social --correlate \
  --rate-limit 1.0 --output html

# Route traffic through Burp Suite or testing proxy
reconx client.com --profile safe --proxy http://127.0.0.1:8080

# Scan specific ports only
reconx client.com --skip-bruteforce
```

### Scenario 6: Social Engineering Assessment

**Goal**: Gather employee intelligence and OSINT for targeted phishing simulations

```bash
# Generate LinkedIn, Twitter dorks and analyze email patterns
reconx target.com --social

# Combine with document metadata to confirm employee naming conventions
reconx target.com --social --metadata
```

---

## 🔬 Security Research

### Scenario 7: WordPress Site Security Audit

**Goal**: Check for exposed WordPress plugins, themes, and version vulnerabilities

```bash
# Deep CMS detection + vulnerability lookup
reconx wordpress-site.com --profile aggressive --bug-hunt --deep-cms

# Check for outdated plugins via WPScan API (set WPSCAN_API_KEY in .env)
reconx wordpress-site.com --profile safe --deep-cms
```

### Scenario 8: Comparative Multi-Target Assessment

**Goal**: Scripted batch analysis across a list of target domains

```bash
# Loop through targets and save individual JSON reports
for domain in site1.com site2.com site3.com; do
    echo "Scanning $domain..."
    reconx "$domain" --profile safe --output json
done
```

---

## 🚨 Incident Response & Threat Hunting

### Scenario 9: Phishing Campaign Triage

**Goal**: Fingerprint attack infrastructure and malicious landing pages

```bash
# Passive fingerprinting of suspected phishing host
reconx malicious-lookalike.com --profile passive --output json

# Check hosting neighbor correlation (other scam sites on same IP)
reconx malicious-lookalike.com --profile passive --correlate

# Analyze logo or image used in phishing kit
reconx kit_logo.png
```

---

## ⚙️ Scan Profiles Guide

Understanding profile intensity is crucial to avoid triggering alerts or knocking services down:

| Profile | Ports Scanned | Path Bruteforce | Fingerprinting | Bug Hunt Allowed | Network Impact |
|---|---|---|---|---|---|
| `passive` | ❌ No | ❌ No | ❌ No (API only) | ❌ No | None (third-party APIs only) |
| `safe` | ❌ No | ❌ No | ✅ Yes (Headers/CMS) | ❌ No | Very low (normal HTTP requests) |
| `active` *(default)* | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No | Moderate (connection bursts) |
| `aggressive` | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes (`--bug-hunt`) | High (fuzzing & testing payloads) |

> ⚠️ **Important rule**: `--bug-hunt` **always requires** `--profile aggressive`. If you pass `--bug-hunt` without `--profile aggressive`, Modular ReconX will return an error or skip bug hunt modules to protect targets from unintended active fuzzing.

```bash
# Correct:
reconx target.com --profile aggressive --bug-hunt

# Incorrect (will trigger warning or skip):
reconx target.com --profile safe --bug-hunt
```

---

## 💡 Pro Tips

### 1. Handling WAF and Rate Limits
Use `--rate-limit` to add deliberate delays between requests, and rotate User-Agents:
```bash
reconx target.com --profile safe --rate-limit 1.5 --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

### 2. Output Formats for Different Audiences
- For programmatic pipelines / jq: `--output json`
- For spreadsheet auditing: `--output csv`
- For executive/client deliverables: `--output html` or `--output pdf`
- For bug bounty submission drafts: `--output md`

### 3. AI-Powered Executive Summaries
Set `GEMINI_API_KEY` in your `.env` file to auto-generate a plain-English risk narrative:
```bash
reconx target.com --profile aggressive --bug-hunt --ai --output html
```

---

## ⚠️ Responsible Use

Always obtain explicit written permission before running active scans against targets you do not own. Consult [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and [SECURITY.md](SECURITY.md) before scanning.
