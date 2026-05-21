# Modular ReconX v1.3.0

Modular ReconX is a modular Python OSINT and bug bounty reconnaissance tool for analyzing domains, websites, and selected local files. It combines passive intelligence gathering, active reconnaissance, vulnerability enrichment, and report generation in one CLI.

> Use this tool only on assets you own or are explicitly authorized to test. Read [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) before running active scans.

## Features

- WHOIS, DNS, SSL certificate, GeoIP, reverse IP, and Wayback discovery
- Wordlist and Certificate Transparency subdomain discovery
- Technology, CMS, WordPress plugin, WAF, and security header checks
- Optional bug-hunt modules for parameters, JavaScript, APIs, forms, CORS, cookies, clickjacking, HPP, and XSS reflection checks
- Cloud storage enumeration for common AWS S3, Azure Blob, and GCP bucket names
- Metadata and image forensics for public files and local files
- GitHub dork/API scanning, breach lookup, and Gemini-powered AI report analysis
- JSON, TXT, CSV, HTML, PDF, and Markdown reports
- Shared HTTP client with proxy, custom User-Agent, retry, timeout, and rate-limit support

## Requirements

- Python 3.8 or newer
- Git
- Optional but recommended: `uv`
- Optional: Docker and Docker Compose
- Optional API keys for Shodan, HIBP, Vulners, ZoomEye, WPScan, Gemini, GitHub, and MaxMind

## Quick Start

### Windows 10/11 PowerShell with uv

`uv` is the fastest path for day-to-day development. It can create `.venv`, install dependencies from `requirements.txt`, and install this project in editable mode.

Install `uv` if needed:

```powershell
winget install astral-sh.uv
uv --version
```

Then set up the project:

```powershell
git clone https://github.com/chrisnov-it/modular_reconx.git
cd modular_reconx

uv venv --python 3.14 .venv
.\.venv\Scripts\Activate.ps1

uv pip install -r requirements.txt
uv pip install -e .

reconx --help
reconx example.com --skip-ports --skip-bruteforce
```

If Python 3.14 is not installed yet, either install it through Python Manager (`py install 3.14`) or let `uv` use another available compatible runtime:

```powershell
uv python list
uv venv --python 3.13 .venv
```

### Windows 10/11 PowerShell with Python Manager

Modern Python on Windows is managed through the Python install manager. Install it from the Microsoft Store, from python.org, or with WinGet:

```powershell
winget install 9NQ7512CXL7T -e
py install --configure -y
py install 3.14
py list
```

Then create a virtual environment for this project. This avoids broken global packages and is especially helpful after moving projects between machines or drives.

```powershell
git clone https://github.com/chrisnov-it/modular_reconx.git
cd modular_reconx

py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .

reconx --help
reconx example.com --skip-ports --skip-bruteforce
```

If `py -3.14` is not available, check installable runtimes:

```powershell
py list --online 3.14
py install 3.14
```

If `python` opens the Microsoft Store instead of Python, run `py install --configure -y`, then check Windows App Execution Aliases for `python.exe`, `python3.exe`, and `py.exe`. Inside an activated venv, `python` should resolve to `.venv\Scripts\python.exe`.

If PowerShell blocks venv activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### Linux / macOS with uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh

git clone https://github.com/chrisnov-it/modular_reconx.git
cd modular_reconx

uv venv --python 3.14 .venv
source .venv/bin/activate

uv pip install -r requirements.txt
uv pip install -e .

reconx --help
reconx example.com --skip-ports --skip-bruteforce
```

### Linux / macOS with standard venv

```bash
git clone https://github.com/chrisnov-it/modular_reconx.git
cd modular_reconx

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .

reconx --help
reconx example.com --skip-ports --skip-bruteforce
```

On Debian, Ubuntu, Kali, Parrot, and other PEP 668 systems, do not install globally with `sudo pip`. Use the venv flow above.

### Reopening the Project Later

After the venv has already been created:

```powershell
cd D:\dev\chrisnov-it\modular_reconx
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
reconx --help
```

Linux/macOS:

```bash
cd /path/to/modular_reconx
source .venv/bin/activate
reconx --help
```

## Configuration

Copy the example environment file and fill only the keys you have:

```powershell
Copy-Item .env.example .env
```

Linux/macOS:

```bash
cp .env.example .env
```

Supported environment variables:

```env
SHODAN_API_KEY=""
HIBP_API_KEY=""
VULNERS_API_KEY=""
ZOOMEYE_API_KEY=""
WPSCAN_API_KEY=""
GEMINI_API_KEY=""
GITHUB_TOKEN=""
MAXMIND_LICENSE_KEY=""
```

Modules that require missing keys will skip or return a note/error instead of stopping the whole scan.

## Data Setup

Some features use local data files. After configuring `.env`, run:

```bash
python download_data.py
python update_db.py
```

Useful variants:

```bash
python download_data.py --geoip
python download_data.py --nvd
python download_data.py --force
```

GeoIP downloads require `MAXMIND_LICENSE_KEY`.

## Docker

Docker is useful when you want a clean, repeatable runtime.

```bash
cp .env.example .env
docker-compose run --rm reconx python download_data.py
docker-compose build
docker-compose run --rm reconx example.com --skip-ports --skip-bruteforce
```

Mounted folders:

- `output/` for generated reports
- `nvd_data/` for downloaded NVD feeds
- `app/data/` for wordlists, GeoIP, and local databases

## Usage

Basic scan:

```bash
reconx example.com
```

Faster, less noisy scan:

```bash
reconx example.com --profile safe
```

Passive-only reconnaissance:

```bash
reconx example.com --profile passive
```

Bug bounty oriented run:

```bash
reconx example.com --profile aggressive --bug-hunt --output md
```

HTML report:

```bash
reconx example.com --output html
```

Proxy, custom User-Agent, and rate limiting:

```bash
reconx example.com --proxy http://127.0.0.1:8080 --rate-limit 1.0 --user-agent "Custom UA"
```

Local file analysis:

```bash
reconx image.jpg
reconx document.pdf
```

Reports are written to `output/`.

## CLI Reference

| Flag | Description |
| ---- | ----------- |
| `--output {json,txt,csv,html,pdf,md}` | Select report format. Default: `json`. |
| `--profile {passive,safe,active,aggressive}` | Select scan intensity. Default: `active`. |
| `--skip-ports` | Skip TCP port scanning. |
| `--skip-bruteforce` | Skip path bruteforcing. |
| `--passive-only` | Alias for `--profile passive`. |
| `--proxy URL` | Proxy URL for modules using the shared HTTP client. |
| `--rate-limit SECONDS` | Minimum delay between shared HTTP client requests. |
| `--user-agent VALUE` | Custom User-Agent for modules using the shared HTTP client. |
| `--correlate` | Correlate reverse IP neighbors by WHOIS similarity. Slow. |
| `--bug-hunt` | Run advanced web security analysis modules. Requires `--profile aggressive`. |
| `--cloud` | Check common cloud storage bucket/container names. |
| `--metadata` | Search public documents and extract PDF/DOCX metadata. |
| `--forensics` | Scrape and analyze images for EXIF data. |
| `--social` | Generate social engineering recon data and dorks. |
| `--reverse` | Add reverse image search links when image URLs are available. |
| `--enhanced-subdomains` | Use a larger subdomain wordlist. Slower. |
| `--ai` | Analyze the final report with Gemini. Requires `GEMINI_API_KEY`. |
| `--github` | Generate GitHub dorks and optionally use GitHub API. |
| `--waf` | Detect common Web Application Firewalls. |
| `--deep-cms` | Fingerprint Drupal, Joomla, Magento, and Moodle. |
| `--version` | Print the Modular ReconX version. |

## Scan Modes

Recommended workflow for authorized testing:

1. Start passive:

    ```bash
    reconx target.com --profile passive --output json
    ```

2. Run safe active checks:

    ```bash
    reconx target.com --profile safe --deep-cms --output html
    ```

3. Run heavier bug-hunt checks only when allowed:

    ```bash
    reconx target.com --profile aggressive --bug-hunt --rate-limit 1.0 --output md
    ```

Profile behavior:

- `passive`: no active HTTP probing beyond passive/API-style discovery.
- `safe`: HTTP fingerprinting and low-impact checks, but no port scan/path bruteforce.
- `active`: default scan profile, including port scan and path bruteforce unless skipped.
- `aggressive`: required for `--bug-hunt` fuzzing and advanced vulnerability checks.

## Project Layout

- `app/scan.py`: CLI entry point and scan orchestration
- `app/modules/`: individual reconnaissance modules
- `app/modules/http_client.py`: shared HTTP client for proxy/rate-limit/user-agent behavior
- `app/data/`: packaged wordlists and local data files
- `nvd_data/`: downloaded NVD JSON feeds
- `output/`: generated reports
- `cache/`: WHOIS/DNS cache files
- `tests/`: test scripts and pytest-style checks
- `scripts/`: demos and maintenance utilities

## Development

Create or activate the venv first, then install in editable mode:

```bash
uv pip install -r requirements.txt
uv pip install -e .
```

Run syntax checks:

```bash
python -m compileall -q app tests scripts
```

Run tests if `pytest` is installed:

```bash
uv pip install pytest
python -m pytest -q
```

## Troubleshooting

### `python` opens Microsoft Store

Install/configure the Python install manager, then recreate the venv:

```powershell
winget install 9NQ7512CXL7T -e
py install --configure -y
py install 3.14
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -e .
```

If commands still resolve to the Store aliases, check Windows Settings -> App Execution Aliases.

### `pip` is missing or commands are not found

If you are using `uv`, reinstall with:

```powershell
uv pip install -r requirements.txt
uv pip install -e .
```

If you are using standard pip, prefer module form inside the venv:

```powershell
python -m ensurepip --default-pip
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### `reconx` is not recognized

Activate the venv and reinstall editable package:

```powershell
.\.venv\Scripts\Activate.ps1
uv pip install -e .
```

### PDF output fails

Install dependencies again. PDF output requires `reportlab`.

```bash
python -m pip install -r requirements.txt
```

### `lxml` asks for Microsoft Visual C++ Build Tools

This usually means pip could not find a prebuilt wheel for your Python version and tried to compile `lxml` from source. On Windows with Python 3.14, use the updated requirements first:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install --only-binary=:all: "lxml>=6.0.2,<7.0.0"
python -m pip install -r requirements.txt
python -m pip install -e .
```

If pip still tries to build from source, either install Microsoft C++ Build Tools or use a Python runtime with wider wheel coverage:

```powershell
py install 3.13
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -e .
```

### GeoIP lookup has no data

Add `MAXMIND_LICENSE_KEY` to `.env`, then run:

```bash
python download_data.py --geoip
```

## Responsible Use

Only scan targets you own or are allowed to test. Some flags are active and can create traffic against the target. Prefer `--passive-only` first, then increase scope gradually based on authorization.

See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and [SECURITY.md](SECURITY.md).

## Author

Reynov Christian / Chrisnov IT Solutions

- Website: <https://chrisnov.com>
