#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Social Engineering Recon module
"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.modules.social_eng import generate_dorks, guess_email_pattern, perform_social_recon


def test_generate_dorks():
    """Test Google Dork generation"""
    print("=" * 60)
    print("Testing Google Dork Generation")
    print("=" * 60)
    
    test_domain = "example.com"
    
    print(f"\n[*] Generating dorks for: {test_domain}")
    dorks = generate_dorks(test_domain)
    
    # Verify structure (updated to match actual module)
    assert isinstance(dorks, dict), "Dorks should be a dictionary"
    assert "linkedin_employees" in dorks, "Should contain LinkedIn employee dorks"
    assert "twitter_employees" in dorks, "Should contain Twitter employee dorks"
    assert "sensitive_files" in dorks, "Should contain sensitive files dorks"
    assert "login_pages" in dorks, "Should contain login pages dorks"
    
    print(f"\n[+] Generated dork categories:")
    for category, dork_list in dorks.items():
        print(f"    - {category}: {len(dork_list)} dorks")
    
    print("\n[+] Sample LinkedIn employee dorks:")
    for dork in dorks["linkedin_employees"][:2]:
        print(f"    {dork}")
    
    print("\n[PASS] Dork generation test passed!")


def test_guess_email_pattern():
    """Test email pattern guessing"""
    print("\n" + "=" * 60)
    print("Testing Email Pattern Analysis")
    print("=" * 60)
    
    # Test with sample emails
    test_emails = [
        "john.doe@example.com",
        "jane.smith@example.com",
        "bob.jones@example.com"
    ]
    
    print(f"\n[*] Analyzing {len(test_emails)} email addresses")
    pattern = guess_email_pattern(test_emails)
    
    # Verify structure
    assert isinstance(pattern, dict), "Pattern should be a dictionary"
    assert "pattern" in pattern, "Should contain pattern field"
    assert "confidence" in pattern, "Should contain confidence field"
    
    print(f"\n[+] Detected pattern: {pattern['pattern']}")
    print(f"[+] Confidence: {pattern['confidence']}")
    
    if pattern.get("sample_size"):
        print(f"[+] Sample size: {pattern['sample_size']}")
    
    print("\n[PASS] Email pattern analysis test passed!")


def test_guess_email_pattern_empty():
    """Test email pattern guessing with no emails"""
    print("\n" + "=" * 60)
    print("Testing Email Pattern Analysis - Empty Input")
    print("=" * 60)
    
    print("\n[*] Testing with empty email list")
    pattern = guess_email_pattern([])
    
    assert isinstance(pattern, dict), "Should return a dictionary"
    assert pattern.get("pattern") == "unknown", "Should return unknown pattern"
    
    print(f"\n[+] Correctly handled empty input: {pattern['pattern']}")
    print("\n[PASS] Empty input test passed!")


def test_perform_social_recon():
    """Test full social engineering recon"""
    print("\n" + "=" * 60)
    print("Testing Full Social Engineering Recon")
    print("=" * 60)
    
    test_domain = "example.com"
    test_emails = ["admin@example.com", "support@example.com"]
    
    print(f"\n[*] Running social recon for: {test_domain}")
    results = perform_social_recon(test_domain, test_emails)
    
    # Verify structure (updated to match actual module)
    assert isinstance(results, dict), "Results should be a dictionary"
    assert "dorks" in results, "Should contain dorks"
    assert "email_analysis" in results, "Should contain email analysis"
    
    print(f"\n[+] Dork categories: {len(results['dorks'])}")
    print(f"[+] Email pattern detected: {results['email_analysis'].get('pattern', 'N/A')}")
    
    print("\n[PASS] Full social recon test passed!")


if __name__ == "__main__":
    try:
        test_generate_dorks()
        test_guess_email_pattern()
        test_guess_email_pattern_empty()
        test_perform_social_recon()
        
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
