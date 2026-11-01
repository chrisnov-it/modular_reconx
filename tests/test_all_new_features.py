#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive test runner for all new v1.2.0 modules
"""

import sys
import os
import subprocess

# Test files to run
TEST_FILES = [
    "test_cloud_enum.py",
    "test_metadata_analysis.py",
    "test_image_forensics.py",
    "test_social_eng.py",
    "test_reverse_image.py",
]


def run_test(test_file):
    """Run a single test file"""
    print(f"\n{'=' * 70}")
    print(f"Running: {test_file}")
    print('=' * 70)
    
    try:
        result = subprocess.run(
            [sys.executable, test_file],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        print(result.stdout)
        
        if result.returncode != 0:
            print(result.stderr)
            return False
        
        return True
        
    except subprocess.TimeoutExpired:
        print(f"[FAIL] Test timed out: {test_file}")
        return False
    except Exception as e:
        print(f"[FAIL] Error running test: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 70)
    print("MODULAR RECONX v1.2.0 - COMPREHENSIVE TEST SUITE")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    for test_file in TEST_FILES:
        if not os.path.exists(test_file):
            print(f"\n[!] Test file not found: {test_file}")
            failed += 1
            continue
        
        if run_test(test_file):
            passed += 1
        else:
            failed += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total tests: {len(TEST_FILES)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print("=" * 70)
    
    if failed > 0:
        print("\n[FAIL] Some tests failed!")
        sys.exit(1)
    else:
        print("\n[PASS] All tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
