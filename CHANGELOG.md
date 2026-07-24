# Changelog

All notable changes to this project will be documented in this file.

## [1.4.0] - 2026-05-21

### 🚀 New Features

- **AI Analysis**: Added `--ai` flag to analyze scan reports using Google Gemini API for executive summaries and risk assessment.
- **GitHub Secret Scanning**: Added `--github` flag to generate dorks and scan for exposed secrets using the GitHub API.
- **WAF Detection**: Added `--waf` flag to detect Web Application Firewalls (Cloudflare, AWS, Akamai, etc.).
- **Enhanced Subdomain Enumeration**: Added `--enhanced-subdomains` flag to use a larger wordlist for deeper discovery.
- **Real API Endpoint Discovery**: Upgraded JS analysis to use regex for finding `/api/v1/`, `axios.get()`, and other endpoint patterns.

### 🛠️ Improvements

- **Windows Compatibility**: Fixed Unicode/Emoji issues in CLI output for Windows CMD/PowerShell.
- **Requirements Cleanup**: Drastically reduced `requirements.txt` from ~370 to 18 essential packages.
- **Performance**: Optimized JS analysis to perform endpoint discovery during the initial pass.

### 🐛 Fixes

- Fixed `UnboundLocalError` in subdomain enumeration module.
- Fixed `SyntaxError` in `scan.py` argument parsing.

## [1.2.0] - 2025-12-03

### 🚀 What's New

- **Docker Support**: Added `Dockerfile` and `docker-compose.yml` for easy containerized deployment.
- **Cloud Enumeration**: Added `--cloud` flag to check for public AWS S3 buckets, Azure Blobs, and GCP Buckets.
- **Metadata Analysis**: Added `--metadata` flag to extract metadata (Author, Software, etc.) from public PDF and DOCX files.
- **Image Forensics**: Added `--forensics` flag to extract EXIF data (GPS, Camera, Software) from images.
- **Social Engineering Recon**: Added `--social` flag to generate Google Dorks and analyze email patterns for corporate targets.
- **Reverse Image Search**: Added `--reverse` flag to generate direct search links for Google Lens, Bing, Yandex, and TinEye.
- **Local File Support**: The tool now accepts local file paths (e.g., `image.jpg`, `report.pdf`) for direct analysis without a domain scan.

### Improvements

- **Unified CLI**: `scan.py` now intelligently handles both domain names and local file paths.
- **Dependency Updates**: Added `PyPDF2`, `python-docx`, and `Pillow` to `requirements.txt`.
- **Refactoring**: Modularized new features into dedicated files in `app/modules/`.

### Fixes

- Fixed an issue with duplicate arguments in `scan.py`.
- Improved error handling for local file analysis.
