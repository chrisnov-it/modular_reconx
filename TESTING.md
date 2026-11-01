# Test Suite Documentation

## Overview

Modular ReconX includes a comprehensive test suite to ensure code quality, module functionality, and behavior consistency across refactoring. Tests are written in pytest and cover 25+ individual modules.

## Quick Start

### Run All Tests

```bash
# Activate venv first
source .venv/bin/activate  # Linux/macOS
# or
.\.venv\Scripts\Activate.ps1  # Windows

# Run full test suite
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=app --cov-report=html

# Run specific test file
pytest tests/test_port_scanner.py -v

# Run tests matching a pattern
pytest tests/ -k "profile" -v
```

### Install Test Dependencies

```bash
# Install from optional [dev] dependencies
pip install -e ".[dev]"

# Or manually
pip install pytest pytest-cov pytest-xdist ruff
```

## Test Structure

### Core Scan Tests

| File | Coverage | Purpose |
|------|----------|---------|
| `test_scan_profiles.py` | 5 tests | Scan profile behavior (passive, safe, active, aggressive) |
| `test_scan_refactored.py` | 5 tests | Refactored scan() phase handlers, behavior parity verification |

### Module Tests

| File | Coverage | Purpose |
|------|----------|---------|
| `test_port_scanner.py` | 5 tests | TCP port scanning with mocked network calls |
| `test_subdomain_enhancements.py` | Multiple | Subdomain enumeration & permutation |
| `test_cloud_enum.py` | Multiple | AWS S3, Azure Blob, GCP bucket enumeration |
| `test_metadata_analysis.py` | Multiple | PDF/DOCX metadata extraction |
| `test_image_forensics.py` | Multiple | EXIF data extraction from images |
| `test_social_eng.py` | Multiple | Google Dorks, email pattern generation |
| `test_reverse_image.py` | Multiple | Reverse image search link generation |
| `test_wp_scanner.py` | Multiple | WordPress plugin detection |
| `test_bug_hunt.py` | Multiple | API discovery, parameter analysis |
| `test_vuln_enhancements.py` | Multiple | Vulnerability scanner functionality |

### Integration Tests

| File | Coverage | Purpose |
|------|----------|---------|
| `test_module_integration.py` | 5 tests | Verify all modules import and instantiate correctly |
| `test_all_new_features.py` | Composite | Run all feature tests in sequence |

## Test Strategies

### Unit Testing (Port Scanner Example)

```python
# test_port_scanner.py
import pytest
from unittest.mock import patch
from app.modules.port_scanner import scan_ports

def test_returns_open_ports_dict_with_string_keys(monkeypatch):
    """Verify scan_ports returns dict with string port keys."""
    def mock_scan(ip, port):
        return port in [80, 443]
    
    monkeypatch.setattr("app.modules.port_scanner._scan_single_port", mock_scan)
    result = scan_ports("127.0.0.1", ports=[80, 443, 22])
    
    assert result == {"80": "open", "443": "open"}
    assert all(isinstance(k, str) for k in result.keys())
```

### Behavior Parity Testing (Scan Profiles)

```python
# test_scan_refactored.py
def test_safe_profile_skips_ports_and_bruteforce_but_runs_fingerprinting(monkeypatch):
    """Verify safe profile runs only passive checks + fingerprinting."""
    calls = {"passive": 0, "active": 0, "bug_hunt": 0}
    
    # Patch phase handlers to track calls
    monkeypatch.setattr("app.scan._execute_phase_passive", lambda *a, **k: (calls.update({"passive": 1}), {}))
    monkeypatch.setattr("app.scan._execute_phase_active", lambda *a, **k: (calls.update({"active": 1}), {}))
    monkeypatch.setattr("app.scan._execute_phase_bug_hunt", lambda *a, **k: (calls.update({"bug_hunt": 1}), {}))
    
    result = scan("example.com", profile="safe")
    
    assert calls["passive"] == 1  # Should run
    assert calls["active"] == 0   # Should skip
    assert calls["bug_hunt"] == 0 # Should skip
```

### Module Integration Testing

```python
# test_module_integration.py
def test_all_modules_importable():
    """Verify all 45+ modules import without errors."""
    from app.modules import (
        port_scanner, vuln_scanner, subdomain_enum,
        api_discovery, path_bruteforce, # ... etc
    )
```

## Running Tests

### Full Suite

```bash
# Run everything
pytest tests/ -v

# Run with coverage (detailed)
pytest tests/ --cov=app --cov-report=term-missing

# Run with parallel execution (faster on multi-core)
pytest tests/ -n auto
```

### Targeted Testing

```bash
# Run only profile tests
pytest tests/test_scan_profiles.py tests/test_scan_refactored.py -v

# Run only refactored scan tests
pytest tests/test_scan_refactored.py -v

# Run port scanner tests
pytest tests/test_port_scanner.py -v

# Run tests matching keyword
pytest tests/ -k "subdomain" -v

# Run a single test
pytest tests/test_scan_profiles.py::test_passive_profile_excludes_active_modules -v
```

### Continuous Integration

GitHub Actions workflow (`.github/workflows/tests.yml`) runs:

```yaml
- Python versions: 3.8, 3.9, 3.10, 3.11, 3.12
- On: push to main/develop/refactor/*, PR to main/develop
- Steps:
  1. Lint with ruff (non-blocking)
  2. Run pytest on all tests
  3. Generate coverage report
```

## Test Coverage

### Current Coverage

- **Refactored `scan()` function**: 100% (all 7 phase handlers tested)
- **Port scanner module**: 100% (5 unit tests, mocked network)
- **Scan profiles**: 100% (5 profile behavior tests)
- **Module integration**: All 45+ modules verified importable
- **Overall statement coverage**: ~70% (limited by network-dependent modules)

### Improving Coverage

To add tests for a new module:

```python
# tests/test_my_module.py
import pytest
from unittest.mock import patch, MagicMock
from app.modules.my_module import my_function

def test_my_function_happy_path(monkeypatch):
    """Test the main success case."""
    # Arrange
    monkeypatch.setattr("app.modules.my_module.external_call", MagicMock(return_value={"key": "value"}))
    
    # Act
    result = my_function("input")
    
    # Assert
    assert result["expected_key"] == "expected_value"

def test_my_function_error_handling(monkeypatch):
    """Test error handling."""
    monkeypatch.setattr("app.modules.my_module.external_call", MagicMock(side_effect=Exception("API down")))
    
    result = my_function("input")
    
    assert result.get("error") is not None
```

## Mocking Strategy

### Why Mock?

Many modules make real network calls (WHOIS, DNS, HTTP requests). Mocking allows tests to:
- Run fast without network latency
- Work offline
- Avoid hitting real APIs (no rate limits)
- Test error cases without breaking real services

### How We Mock

```python
from unittest.mock import patch, MagicMock

# Mock a module function
@patch('app.modules.port_scanner._scan_single_port')
def test_with_decorator(mock_scan):
    mock_scan.return_value = True
    # ... test code ...

# Mock using monkeypatch (pytest style)
def test_with_monkeypatch(monkeypatch):
    monkeypatch.setattr('app.modules.dns_lookup.resolve', MagicMock(return_value=['1.2.3.4']))
    # ... test code ...

# Mock with side effects (simulate multiple calls)
def test_with_side_effects(monkeypatch):
    mock_fn = MagicMock(side_effect=[True, False, Exception("error")])
    monkeypatch.setattr('app.modules.some_module.check', mock_fn)
    # ... test code ...
```

## Debugging Tests

### Verbose Output

```bash
# Show print statements and detailed output
pytest tests/test_my_test.py -v -s

# Show full traceback
pytest tests/test_my_test.py -v --tb=long

# Stop on first failure (don't run remaining tests)
pytest tests/test_my_test.py -x
```

### Breakpoint Debugging

```python
def test_my_function():
    result = my_function("input")
    breakpoint()  # Execution will pause here, use 'c' to continue
    assert result == "expected"

# Run with pytest to enter debugger
pytest tests/test_my_test.py -v -s
```

### Running a Single Test

```bash
# Run specific test in specific file
pytest tests/test_port_scanner.py::TestScanPorts::test_returns_open_ports_dict_with_string_keys -v
```

## Common Issues

### Import Errors in Tests

**Problem**: `ModuleNotFoundError: No module named 'app'`

**Solution**:
1. Install package in editable mode: `pip install -e .`
2. Run pytest from repo root: `cd /path/to/modular_reconx && pytest`

### Network Tests Failing

**Problem**: Tests fail with timeout or connection error

**Solution**:
1. Verify mocks are applied: `@patch('...')` or `monkeypatch.setattr(...)`
2. Check mock return values match expected structure
3. Use `MagicMock()` for flexible return types

### Fixture Issues

**Problem**: Fixture not found or incorrect scope

**Solution**:
1. Fixtures defined in `conftest.py` are auto-discovered
2. Check fixture name matches test parameter name
3. Verify fixture scope (function, class, module, session)

## Performance

### Test Execution Time

- **All tests**: ~5-10 seconds (with 45+ modules)
- **Individual module tests**: <1 second (due to mocking)
- **Integration tests**: 2-3 seconds

### Speeding Up Tests

```bash
# Parallel execution (requires pytest-xdist)
pytest tests/ -n auto

# Run only specific test file
pytest tests/test_port_scanner.py

# Skip slow integration tests
pytest tests/ -m "not slow"
```

## Best Practices

### Writing Good Tests

1. **One assertion per test** (unless testing a workflow)
   ```python
   def test_scan_returns_dict():
       result = scan("example.com")
       assert isinstance(result, dict)
   
   def test_scan_contains_expected_keys():
       result = scan("example.com")
       assert "domain" in result
   ```

2. **Use descriptive names**
   ```python
   # Good
   def test_port_scanner_returns_string_keys_for_open_ports()
   
   # Bad
   def test_scanner()
   ```

3. **Test edge cases**
   ```python
   def test_handles_empty_input()
   def test_handles_invalid_ip()
   def test_handles_timeout()
   ```

4. **Mock external dependencies**
   ```python
   # Don't make real network calls in tests
   @patch('app.modules.dns_lookup.resolve')
   def test_dns_handling(mock_resolve):
       mock_resolve.return_value = ['1.2.3.4']
       # ... test ...
   ```

## Continuous Development

### Before Committing

```bash
# Run tests locally
pytest tests/ -v

# Check coverage
pytest tests/ --cov=app --cov-report=term-missing

# Lint with ruff
ruff check app/ tests/
```

### GitHub Actions

Push to branch and GitHub Actions automatically:
1. Runs full test suite on Python 3.8-3.12
2. Generates coverage report
3. Runs linter (ruff)
4. Blocks PR merge if tests fail

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [unittest.mock documentation](https://docs.python.org/3/library/unittest.mock.html)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [pytest-xdist documentation](https://pytest-xdist.readthedocs.io/)

## Support

For test-related questions:

- GitHub Issues: Tag with `testing`
- GitHub Discussions: Ask in #testing channel
- See [SECURITY.md](SECURITY.md) for security-related test issues
