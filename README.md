# Modular ReconX v1.4.1

Modular ReconX is a modular Python OSINT and bug bounty reconnaissance tool for analyzing domains, websites, and selected local files. It combines passive intelligence gathering, active reconnaissance, vulnerability enrichment, and multi-format report generation in a unified CLI.

> ⚠️ **Authorized Use Only**: Use this tool only on assets you own or are explicitly authorized to test. Read [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and [SECURITY.md](SECURITY.md) before running active scans.

---

## 🚀 Features

- **Passive Intelligence**: WHOIS, DNS records, SSL certificates, GeoIP, reverse IP lookups, Wayback Machine archives.
- **Subdomain Reconnaissance**: Wordlist brute-force, Certificate Transparency log monitoring, and combinatorial permutations.
- **Active Fingerprinting**: Web tech stack detection, CMS identification (WordPress, Drupal, Joomla, Magento), WAF detection, and security header audit.
- **Port & Path Discovery**: Multi-threaded TCP port scanner and common web path brute-forcing.
- **Advanced Bug-Hunt**: Parameter analysis, JavaScript endpoint discovery, API extraction, CORS misconfigurations, GraphQL introspection, and reflected XSS checks.
- **Cloud Enumeration**: Automated checks for exposed AWS S3, Azure Blob, and Google Cloud Storage buckets.
- **Local & Remote Forensics**: Document metadata extraction (PDF, DOCX), image EXIF forensics, and reverse image search lookups.
- **AI-Powered Analysis**: Automated executive summaries and risk ratings via Google Gemini API (`--ai`).
- **Flexible Reporting**: Output formats in JSON, HTML, PDF, Markdown, CSV, and TXT.
- **Network Controls**: Global HTTP proxy support, customizable User-Agent, request timeouts, and adaptive rate-limiting.

---

## 📋 Requirements

- Python **3.8** through **3.13**
- Git
- Optional: `uv` (recommended for 10-100x faster package installation)
- Optional API keys (Shodan, Vulners, HIBP, Gemini, ZoomEye, WPScan, GitHub, MaxMind)

---

## ⚡ Quick Start

### 1. Installation (Linux / macOS)

Using standard Python virtual environments:

```bash
# Clone the repository
git clone https://github.com/chrisnov-it/modular_reconx.git
cd modular_reconx

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip and install package
python -m pip install --upgrade pip
pip install -e .

# Verify installation
reconx --help
```

*(Optional)* If using `uv`:
```bash
uv venv .venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### 2. Installation (Windows PowerShell)

```powershell
# Clone the repository
git clone https://github.com/chrisnov-it/modular_reconx.git
cd modular_reconx

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install
python -m pip install --upgrade pip
pip install -e .

# Verify
reconx --help
```

> **PowerShell Execution Policy Tip**: If `.venv\Scripts\Activate.ps1` gives an execution policy error, run:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

---

## ⚙️ Configuration & API Keys

Copy the sample environment file and configure any API keys you possess:

```bash
cp .env.example .env
```

Available keys (all are optional; missing keys will cleanly skip the associated module):
```env
SHODAN_API_KEY=""         # Shodan internet intelligence
HIBP_API_KEY=""           # HaveIBeenPwned breach checks
VULNERS_API_KEY=""        # Vulners CVE search
ZOOMEYE_API_KEY=""        # ZoomEye host search
WPSCAN_API_KEY=""         # WPScan WordPress database
GEMINI_API_KEY=""         # Google Gemini AI summary
GITHUB_TOKEN=""           # GitHub API token for secret hunting
MAXMIND_LICENSE_KEY=""    # MaxMind GeoLite2 database
```

---

## 🎯 Usage & Scan Profiles

### Scan Intensity Profiles

Modular ReconX uses profiles to prevent unintended aggressive traffic:

| Profile | Port Scan | Path Brute-force | Fingerprinting | Bug Hunt Allowed | Network Footprint |
|---|---|---|---|---|---|
| `passive` | ❌ No | ❌ No | ❌ No | ❌ No | Zero packet to target |
| `safe` | ❌ No | ❌ No | ✅ Yes | ❌ No | Minimal (regular HTTP) |
| `active` *(default)* | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No | Moderate |
| `aggressive` | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes (`--bug-hunt`) | Heavy (fuzzing & testing) |

### Common Commands

**1. Basic Active Scan (Default):**
```bash
reconx example.com
```

**2. Fast, Low-Noise Scan (Safe for Production):**
```bash
reconx example.com --profile safe --output html
```

**3. Stealth Passive-Only Reconnaissance:**
```bash
reconx example.com --profile passive --output json
```

**4. Comprehensive Bug Bounty Scan:**
```bash
reconx example.com --profile aggressive --bug-hunt --output md
```

**5. Speed up by skipping slow tasks:**
```bash
reconx example.com --skip-ports --skip-bruteforce
```

**6. Local File Analysis (No domain scan needed):**
```bash
reconx sample_photo.jpg       # Extracts GPS & camera EXIF data
reconx internal_doc.pdf       # Extracts author & software metadata
```

All generated reports are saved into the `output/` directory.

---

## 🗂️ CLI Options Reference

| Flag | Description |
| ---- | ----------- |
| `--output {json,txt,csv,html,pdf,md}` | Choose report format (Default: `json`). |
| `--profile {passive,safe,active,aggressive}` | Choose scan intensity (Default: `active`). |
| `--skip-ports` | Skip TCP port scanning. |
| `--skip-bruteforce` | Skip HTTP path brute-forcing. |
| `--passive-only` | Alias for `--profile passive`. |
| `--bug-hunt` | Run advanced web modules (APIs, CORS, GraphQL). Requires `--profile aggressive`. |
| `--cloud` | Enumerate public AWS S3, Azure Blob, and GCP buckets. |
| `--metadata` | Scrape public documents and extract PDF/DOCX metadata. |
| `--forensics` | Extract EXIF and forensic details from images. |
| `--social` | Generate social engineering reconnaissance dorks. |
| `--reverse` | Generate reverse image search links for images. |
| `--enhanced-subdomains` | Use combinatorial permutation and broader wordlists. |
| `--waf` | Detect Web Application Firewalls (Cloudflare, AWS, etc.). |
| `--deep-cms` | Fingerprint CMS specifics (Drupal, Joomla, Magento, WordPress). |
| `--ai` | Generate an AI executive summary (Requires `GEMINI_API_KEY`). |
| `--github` | Search for exposed secrets via GitHub dorks/API. |
| `--rate-limit SECONDS` | Delay between HTTP requests to prevent blocking. |
| `--proxy URL` | Route HTTP traffic through a proxy (e.g. `http://127.0.0.1:8080`). |
| `--user-agent VALUE` | Custom HTTP User-Agent string. |
| `--version` | Display version information. |

---

## 🏗️ Architecture & Project Layout

```text
modular_reconx/
├── app/
│   ├── scan.py                # Core orchestrator (split into 7 modular phase handlers)
│   ├── modules/               # 45+ specialized OSINT & analysis modules
│   │   ├── http_client.py     # Shared HTTP client (rate-limiting, proxy, retries)
│   │   ├── port_scanner.py    # Multi-threaded TCP port scanner
│   │   ├── vuln_scanner.py    # Local SQLite CVE cache + Vulners fallback
│   │   ├── api_discovery.py   # JavaScript & HTML endpoint discovery
│   │   └── ...
│   └── data/                  # Packaged wordlists and lookup tables
├── tests/                     # Comprehensive pytest test suite (15+ verified tests)
├── .github/workflows/         # GitHub Actions CI matrix (Python 3.8 - 3.12)
├── pyproject.toml             # Modern PEP 621 packaging (Hatchling backend)
├── EXAMPLES.md                # Detailed real-world scanning scenarios
├── TESTING.md                 # Test suite documentation & development guide
├── AUDIT_DUPLICATES.md        # Codebase audit & module redundancy analysis
└── RESPONSIBLE_USE.md         # Ethical usage guidelines
```

---

## 🧪 Testing & Development

Install developer tools:
```bash
pip install -e ".[dev]"
```

Run tests with `pytest`:
```bash
# Run unit tests and scan behavior checks
pytest tests/ -v

# Run with test coverage
pytest tests/ --cov=app --cov-report=term
```

Lint with `ruff`:
```bash
ruff check app/ tests/
```

---

## 🛡️ Responsible Disclosure & Ethics

Modular ReconX is built for security researchers, penetration testers, and system administrators with explicit authorization. Never scan targets you do not own or have permission to assess.

Refer to [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and [SECURITY.md](SECURITY.md) for full guidelines.

---

## 👤 Author & Support

Created and maintained by **Reynov Christian** ([Chrisnov IT Solutions](https://chrisnov.com)).

- Website: [https://chrisnov.com](https://chrisnov.com)
- GitHub: [@chrisnov-it](https://github.com/chrisnov-it)
- Report Issues: [GitHub Issues](https://github.com/chrisnov-it/modular_reconx/issues)
