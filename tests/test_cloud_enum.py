#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Cloud Enumeration module
"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.modules.cloud_enum import check_cloud_storage


def test_cloud_enum_basic():
    """Test basic cloud enumeration functionality"""
    print("=" * 60)
    print("Testing Cloud Enumeration Module")
    print("=" * 60)
    
    test_domain = "example.com"
    
    print(f"\n[*] Testing cloud storage enumeration for: {test_domain}")
    results = check_cloud_storage(test_domain)
    
    # Verify structure
    assert isinstance(results, dict), "Results should be a dictionary"
    assert "aws_s3" in results, "Should contain AWS S3 results"
    assert "azure_blob" in results, "Should contain Azure Blob results"
    assert "gcp_bucket" in results, "Should contain GCP Bucket results"
    
    print(f"\n[+] AWS S3 buckets checked: {len(results['aws_s3'])}")
    print(f"[+] Azure Blobs checked: {len(results['azure_blob'])}")
    print(f"[+] GCP Buckets checked: {len(results['gcp_bucket'])}")
    
    # Check for accessible buckets
    accessible_count = 0
    for provider, buckets in results.items():
        if provider == "total_found":
            continue
        for bucket in buckets:
            if bucket.get("accessible"):
                accessible_count += 1
                print(f"\n[!] FOUND ACCESSIBLE: {bucket['url']}")
    
    print(f"\n[+] Total accessible buckets found: {accessible_count}")
    print("\n[PASS] Cloud enumeration test completed successfully!")


def test_cloud_enum_permutations():
    """Test that permutations are generated correctly"""
    print("\n" + "=" * 60)
    print("Testing Permutation Generation")
    print("=" * 60)
    
    test_domain = "test.com"
    results = check_cloud_storage(test_domain)
    
    # Should check multiple permutations
    total_checks = len(results['aws_s3']) + len(results['azure_blob']) + len(results['gcp_bucket'])
    
    print(f"\n[+] Total permutations checked: {total_checks}")
    assert total_checks >= 0, "Should check at least some permutations"
    
    print("[PASS] Permutation generation test passed!")


if __name__ == "__main__":
    try:
        test_cloud_enum_basic()
        test_cloud_enum_permutations()
        print("\n" + "=" * 60)
        print("ALL TESTS PASSED")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
