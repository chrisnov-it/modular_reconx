# 🕵️ Modular ReconX v1.3.0

![Modular ReconX Splash Screen](splash.png)

**Modular ReconX** is a modular OSINT tool based on Python for performing a complete analysis of a domain or website using open-source intelligence techniques.

## ✨ Features

- ✅ WHOIS Lookup (with fallback)
- ✅ DNS Record Scan (A, MX, NS, TXT)
- ✅ BuiltWith-like Detection (tech stack & CMS)
- ✅ GeoIP Lookup (server location)
- ✅ Port Scanner (21-8080)
- ✅ Subdomain Enumerator (wordlist-based)
- ✅ Certificate Transparency Log Monitoring (enhanced subdomain discovery)
- ✅ Reverse IP Lookup (HackerTarget & ViewDNS fallback)
- ✅ Directory/Path Bruteforce (/admin, /login, etc.)
- ✅ SSL Certificate Info (common name & issuer)
- ✅ Social Media Finder (Facebook, IG, Twitter, LinkedIn, TikTok, Threads, YouTube, Telegram)
- ✅ Breach Email Check (optional WHOIS email scan with HIBP and Mozilla Monitor fallback)
- ✅ Vulnerability Check (via Vulners API for detected tech with offline NVD database support)
- ✅ Wayback Machine URL History
- ✅ Enhanced WordPress Plugin Vulnerability Scanner (automatic plugin detection via multiple methods and vulnerability assessment)
- ✅ Domain Correlation (filter reverse IP results by WHOIS similarity)
- ✅ Caching Mechanism (1-hour cache for DNS and WHOIS lookups)
- ✅ Input Validation (domain format validation)
- ✅ Improved Error Handling
- ✅ Enhanced Privacy Mode (passive-only scanning to avoid detection)
- ✅ Proxy Support (SOCKS/HTTP proxy for anonymizing requests)
- ✅ User-Agent Rotation (automatic rotation to avoid detection)
- ✅ Rate Limiting Controls (configurable delays between requests)
- ✅ Enhanced Vulnerability Scanning (local exploit database with offline searchsploit-like functionality)
- ✅ Subdomain Enumeration Enhancements (permutation-based discovery and enhanced wordlists)
- ✅ Parameter Analysis (identifies potential injection points)
- ✅ JavaScript Analysis (finds sensitive data and security issues in JS files)
- ✅ API Endpoint Discovery (uncovers hidden API endpoints)
- ✅ Security Headers Analysis (checks for proper HTTP security headers)
- ✅ Form Analysis (identifies security issues in HTML forms)
- ✅ CORS Misconfiguration Checker (detects dangerous CORS policies)
- ✅ Cookie Security Analysis (analyzes cookie security attributes)
- ✅ Clickjacking Protection Checker (verifies anti-clickjacking measures)
- ✅ HTTP Parameter Pollution Detector (identifies parameter duplication vulnerabilities)
- ✅ Parameter Analysis (identifies potential injection points)
- ✅ JavaScript Analysis (finds sensitive data and security issues in JS files)
- ✅ API Endpoint Discovery (uncovers hidden API endpoints)
- ✅ Security Headers Analysis (checks for proper HTTP security headers)
- ✅ Form Analysis (identifies security issues in HTML forms)
- ✅ CORS Misconfiguration Checker (detects dangerous CORS policies)
- ✅ Cookie Security Analysis (analyzes cookie security attributes)
- ✅ Clickjacking Protection Checker (verifies anti-clickjacking measures)
- ✅ **Cloud Enumeration** (AWS S3, Azure Blob, GCP Bucket)
- ✅ **Metadata Analysis** (PDF/DOCX metadata extraction)
- ✅ **Image Forensics** (EXIF data extraction)
- ✅ **Social Engineering Recon** (Dorks & Email Pattern Analysis)
- ✅ **Reverse Image Search** (Google Lens, Bing, Yandex, TinEye links)
- ✅ **Docker Support** (Containerized deployment)
- ✅ **Local File Analysis** (Analyze local images and documents)
- ✅ **AI Reporting** (Google Gemini analysis of scan results)
- ✅ **GitHub Scanning** (Secret scanning & dorks)
- ✅ **WAF Detection** (Web Application Firewall identification)
- ✅ **HTML/CSV Reports** (Beautiful dashboards and spreadsheet-ready output)

## ⚙️ Setup

### 1. Prerequisites

- Python 3.8+

### 2. Installation

#### Option A: Standard Installation

```bash
# Clone the repository
git clone https://github.com/chrisnov-it/modular_reconx.git
cd modular_reconx

# Install dependencies
pip install -r requirements.txt

# Install as a package
pip install -e .
```

This installation method allows you to run the tool from anywhere using:

```bash
reconx example.com
# or
modular-reconx example.com
```

#### Option B: Docker Installation (Recommended)

Docker provides an isolated environment with all dependencies pre-configured.

```bash
# Clone the repository
git clone https://github.com/chrisnov-it/modular_reconx.git
cd modular_reconx

# 1. Setup Environment
cp .env.example .env
# Edit .env and verify/add your API Keys

# 2. Download Data Dependencies (Using Docker)
# This populates the local nvd_data/ and app/data/ folders which are mounted into the container
docker-compose run --rm reconx python download_data.py

# 3. Build & Run
docker-compose build
docker-compose run --rm reconx example.com
```

**Docker Benefits:**

- **Clean & Fast Builds**: Uses `.dockerignore` to keep images small (~100MB layer).
- **Persistent Data**: NVD database and GeoIP files are stored on your host machine (in `nvd_data/` and `app/data/`) and mounted to the container. You only need to download them once.
- **Isolation**: strict separation from host system packages.

### 3. Configuration (API Keys)

Some modules in Modular ReconX require API keys to function. The tool uses a `.env` file to store these keys securely.

1. Copy the `.env.example` file to a new file named `.env`. You can use this command in your terminal:

    ```bash
    cp .env.example .env
    ```

2. Open the newly created `.env` file with a text editor.

3. Fill in the API keys you have. If you don't have any of the keys, just leave them empty, and the corresponding modules will be automatically skipped.

    ```env
    SHODAN_API_KEY="YourShodanAPIKeyHere"
    HIBP_API_KEY="YourHaveIBeenPwnedAPIKeyHere"
    VULNERS_API_KEY="YourVulnersAPIKeyHere"
    ZOOMEYE_API_KEY="YourZoomEyeAPIKeyHere"
    WPSCAN_API_KEY="YourWPScanAPIKeyHere"
    GEMINI_API_KEY="YourGeminiAPIKeyHere"
    GITHUB_TOKEN="YourGitHubTokenHere"
    ```

    - **VULNERS_API_KEY**: Required for vulnerability scanning. A free key can be obtained from Vulners.com.
    - **WPSCAN_API_KEY**: Required for WordPress-specific scanning. A free key (25 requests/day) can be obtained from WPScan.com.
    - **GEMINI_API_KEY**: Required for AI Analysis features (Google AI Studio).
    - **GITHUB_TOKEN**: Optional for higher rate limits on GitHub scanning.

### 4. Download Data Dependencies

Some modules require local databases to function. A script is provided to download and set up these dependencies automatically.

1. **GeoLite2 Database (for GeoIP lookups):**
    - Sign up for a free [MaxMind account](https://www.maxmind.com/en/geolite2/signup) to get a license key.
    - Add your key to the `.env` file:

        ```env
        MAXMIND_LICENSE_KEY="YourMaxMindLicenseKeyHere"
        ```

2. **Run the Download Script:**

    ```bash
    python download_data.py
    ```

    This command will download the GeoLite2 database and the latest NVD vulnerability feeds.

    **Note:** The script automatically skips existing files to save bandwidth. To force a redownload of all files, use the `--force` flag:

    ```bash
    python download_data.py --force
    ```

    You can also run `python download_data.py --nvd` or `python download_data.py --geoip` to download them separately.

3. **Update the NVD Database:**
    After downloading the NVD JSON feeds, it's recommended to process them into the local database for the tool to use.

    ```bash
    python update_db.py
    ```

## 🐧 Linux Specific Instructions

### Installation on Linux (Important)

Since **PEP 668** was adopted by many Linux distributions (Debian 12, Ubuntu 23.04+, Linux Mint 22+, Kali, Parrot OS, etc.), installing Python packages globally using `pip` is strongly discouraged and often restricted to prevent conflicts with the system package manager (`apt`, `dnf`, `pacman`).

#### Recommended Method: Virtual Environment

We **strongly recommend** using a virtual environment for installation. This method isolates project dependencies from your system, preventing conflicts and permission issues.

```bash
# 1. Install pip and venv if not present
sudo apt install python3-pip python3-venv -y

# 2. Clone the repository
git clone https://github.com/chrisnov-it/modular_reconx.git
cd modular_reconx

# 3. Create a virtual environment
python3 -m venv .venv

# 4. Activate the virtual environment
source .venv/bin/activate

# 5. Install the tool in editable mode
pip install -e .

# 6. Run the tool
reconx example.com
```

To exit the virtual environment when you're done:

```bash
deactivate
```

#### Alternative: Pipx

If you want to install it as a command-line tool usable from anywhere without manually activating a virtual environment, `pipx` is an excellent alternative.

```bash
# Install pipx
sudo apt install pipx
pipx ensurepath

# Install modular-reconx via pipx
pipx install git+https://github.com/chrisnov-it/modular_reconx.git
```

### Running with Correct Permissions

Some modules (like detailed port scanning) may require root privileges. If you installed via the Virtual Environment method:

```bash
# While inside the virtual environment (.venv)
sudo .venv/bin/reconx example.com
```

### Troubleshooting

If you encounter "Externally Managed Environment" errors, it means you are trying to install system-wide without a virtual environment. Please use the **Recommended Method** above.

## 🚀 How to Run

> **💡 Check out [EXAMPLES.md](EXAMPLES.md) for 14+ real-world bug bounty and security assessment scenarios!**

```bash
reconx example.com
# or
modular-reconx example.com
```

To speed up the scan, you can skip the slower modules like port scanning and path bruteforcing:

```bash
reconx example.com --skip-ports --skip-bruteforce
```

To generate reports in different formats:

```bash
# Generate HTML report with visualizations (Best for viewing)
reconx example.com --output html

# Generate CSV reports for spreadsheet analysis
reconx example.com --output csv
```

To enable domain correlation (compare WHOIS data of reverse IP results):

```bash
reconx example.com --correlate
```

To enable comprehensive bug hunting mode with advanced security analysis:

```bash
reconx example.com --bug-hunt
```

For enhanced privacy and security, you can use passive-only scanning mode:

```bash
reconx example.com --passive-only
```

To use a proxy for anonymizing requests:

```bash
reconx example.com --proxy http://127.0.0.1:8080
```

To set a custom user agent:

```bash
reconx example.com --user-agent "Custom User Agent String"
```

To add rate limiting between requests:

```bash
reconx example.com --rate-limit 1.0
```

You can combine multiple privacy and security options:

```bash
reconx example.com --passive-only --proxy http://127.0.0.1:8080 --rate-limit 0.5
```

```bash
reconx example.com --correlate
```

Results are saved as a JSON file in the `output/` directory.

## 🕵️ Advanced Usage

### Cloud & Metadata

```bash
reconx example.com --cloud --metadata
```

### Forensics & Social Engineering

```bash
reconx example.com --forensics --social --reverse
```

### HTML Reporting (Dashboard)

```bash
reconx example.com --output html
```

### Local File Analysis

You can run analysis directly on local files:

```bash
# Analyze an image for EXIF data
reconx image.jpg

# Analyze a document for metadata
reconx report.pdf
```

## 📋 CLI Reference

| Flag | Description | Example |
| ---- | ----------- | ------- |
| `--output` | Output format: `json`, `txt`, `csv`, `html` | `reconx target.com --output html` |
| `--cloud` | Enable cloud storage enumeration (AWS/Azure/GCP) | `reconx example.com --cloud` |
| `--metadata` | Extract metadata from public documents (PDF/DOCX) | `reconx example.com --metadata` |
| `--forensics` | Analyze images for EXIF data | `reconx example.com --forensics` |
| `--social` | Generate Google Dorks and analyze email patterns | `reconx example.com --social` |
| `--reverse` | Generate reverse image search links | `reconx example.com --forensics --reverse` |
| `--ai` | Enable AI Analysis (Gemini) | `reconx example.com --ai` |
| `--github` | Enable GitHub Secret Scanning | `reconx example.com --github` |
| `--waf` | Enable WAF Detection | `reconx example.com --waf` |
| `--enhanced-subdomains` | Use larger wordlists for enumeration | `reconx example.com --enhanced-subdomains` |
| `--param-analysis` | Analyze URL parameters for injection vulnerabilities | `reconx example.com --param-analysis` |
| `--js-analysis` | Analyze JavaScript files for security issues | `reconx example.com --js-analysis` |
| `--api-discovery` | Discover hidden API endpoints | `reconx example.com --api-discovery` |
| `--security-headers` | Check HTTP security headers | `reconx example.com --security-headers` |
| `--form-analysis` | Analyze HTML forms for security issues | `reconx example.com --form-analysis` |
| `--cors-check` | Check for CORS misconfigurations | `reconx example.com --cors-check` |
| `--cookie-analysis` | Analyze cookie security attributes | `reconx example.com --cookie-analysis` |
| `--clickjacking-check` | Check for clickjacking protection | `reconx example.com --clickjacking-check` |
| `--hpp-check` | Check for HTTP Parameter Pollution | `reconx example.com --hpp-check` |

### Combined Usage Examples

```bash
# Full OSINT scan with all new features and HTML report
reconx example.com --cloud --metadata --forensics --social --reverse --output html

# Cloud security assessment
reconx example.com --cloud

# Document intelligence gathering
reconx example.com --metadata

# Image forensics investigation
reconx example.com --forensics --reverse

# Social engineering recon
reconx example.com --social

# Local file analysis (auto-detects file type)
reconx suspicious_image.jpg
reconx leaked_document.pdf
```

## 🆕 What's New in v1.3.0

### 🚀 Major New Features

#### HTML & CSV Reporting

- **Beautiful HTML Dashboards**: View your scan results in a modern, card-based interface.
- **CSV Export**: Flattened data export perfect for Excel or spreadsheet analysis.

#### AI Analysis (Powered by Gemini)

- **Automatic Interpretation**: The tool now sends scan results to Google's Gemini AI to generate an "Executive Summary".
- **Risk Assessment**: Get a second opinion on the severity of findings from an AI security expert.

#### GitHub Scanning

- **Secret Detection**: Scans public repositories for leaked API keys and secrets.
- **Exposure Check**: Finds repositories related to the target domain.

#### Web Application Firewall (WAF) Detection

- **Protection Analysis**: Identifies if the target is protected by Cloudflare, AWS WAF, Akamai, etc.

#### Cloud Storage Enumeration

- **AWS S3 Bucket Discovery**: Automatically checks for public S3 buckets
- **Azure Blob Storage**: Detects exposed Azure storage containers
- **GCP Bucket Scanning**: Identifies publicly accessible Google Cloud buckets

#### Document Metadata Analysis

- **PDF/DOCX Extraction**: Extracts author, creator, creation date, and software info from public documents.
- **Local File Support**: Analyze documents directly from your filesystem.

#### Image Forensics & Reverse Search

- **EXIF Data**: Pulls GPS coordinates, camera model, and timestamps.
- **Reverse Search**: Generates links for Google Lens, Bing, Yandex, and TinEye.

### 🔧 Improvements

- **Docker Efficiency**: Massive reduction in image size using volume mounting strategy.
- **PEP 668 Compliance**: Updates for modern Linux distributions.
- **CSV/HTML Ouput**: Integrated natively into the CLI.
- **Windows Unicode Fixes**: Resolved character encoding issues on Windows consoles.

---

## 📜 What's New in v1.1

(See CHANGELOG.md for older history)

## 📁 Directory Structure

- `app/data/`: Contains wordlists, GeoIP database, and NVD vulnerability database
- `app/modules/`: Individual OSINT modules
- `nvd_data/`: NVD JSON data files for offline vulnerability checking
- `output/`: JSON/HTML/CSV scan reports
- `app/scan.py`: Main execution script
- `setup.py`: Package installation script
- `requirements.txt`: Python dependencies
- `.env`: Configuration file for API keys
- `tests/`: Unit tests
- `scripts/`: Utility scripts (data download, updates, demos)

## 🤝 Contributing

Feel free to fork the repository and submit pull requests. For major changes, please open an issue first to discuss what you would like to change.

## 👤 Author

### **Reynov Christian aka BabyDev**

- Business: Chrisnov IT Solutions
- Website: <https://chrisnov.com>
