# Test Suite Documentation

## Overview

This document describes the comprehensive test suite for Modular ReconX v1.2.0 new features.

## Test Files

### 1. test_module_integration.py

**Purpose**: Verifies all new v1.2.0 modules can be imported successfully.

**Tests**:

- Import verification for all 5 new modules
- HTTP client configuration test

**Run**: `python test_module_integration.py`

### 2. test_cloud_enum.py

**Purpose**: Tests cloud storage enumeration functionality.

**Tests**:

- Basic cloud enumeration (AWS S3, Azure Blob, GCP Bucket)
- Permutation generation verification
- Result structure validation

**Run**: `python test_cloud_enum.py`

### 3. test_metadata_analysis.py

**Purpose**: Tests document metadata extraction.

**Tests**:

- PDF metadata extraction
- DOCX metadata extraction
- Unsupported file type handling

**Run**: `python test_metadata_analysis.py`

### 4. test_image_forensics.py

**Purpose**: Tests image EXIF data extraction.

**Tests**:

- Local image analysis
- Image discovery on domains
- Remote image analysis

**Run**: `python test_image_forensics.py`

### 5. test_social_eng.py

**Purpose**: Tests social engineering reconnaissance tools.

**Tests**:

- Google Dork generation (LinkedIn, Twitter, files, login pages)
- Email pattern analysis
- Empty input handling
- Full social recon workflow

**Run**: `python test_social_eng.py`

### 6. test_reverse_image.py

**Purpose**: Tests reverse image search link generation.

**Tests**:

- Basic link generation (Google, Bing, Yandex, TinEye)
- Special character URL encoding
- HTTPS URL handling

**Run**: `python test_reverse_image.py`

### 7. test_all_new_features.py

**Purpose**: Comprehensive test runner for all new modules.

**Run**: `python test_all_new_features.py`

## Running All Tests

### Individual Tests

```bash
python test_module_integration.py
python test_cloud_enum.py
python test_metadata_analysis.py
python test_image_forensics.py
python test_social_eng.py
python test_reverse_image.py
```

### All Tests at Once

```bash
python test_all_new_features.py
```

## Test Coverage

| Module | Test File | Status |
|--------|-----------|--------|
| cloud_enum.py | test_cloud_enum.py | ✓ |
| metadata_analysis.py | test_metadata_analysis.py | ✓ |
| image_forensics.py | test_image_forensics.py | ✓ |
| social_eng.py | test_social_eng.py | ✓ |
| reverse_image.py | test_reverse_image.py | ✓ |
| All modules | test_module_integration.py | ✓ |

## Notes

- All tests use ASCII characters only to avoid Windows encoding issues
- Tests create temporary files when needed and clean up after themselves
- Network-dependent tests (like remote image analysis) gracefully handle failures
- Tests verify both structure and functionality of each module
