#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Reverse Image Search module
"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.modules.reverse_image import generate_reverse_links


def test_generate_reverse_links():
    """Test reverse image search link generation"""
    print("=" * 60)
    print("Testing Reverse Image Search Link Generation")
    print("=" * 60)
    
    test_url = "https://example.com/image.jpg"
    
    print(f"\n[*] Generating reverse search links for: {test_url}")
    links = generate_reverse_links(test_url)
    
    # Verify structure
    assert isinstance(links, dict), "Links should be a dictionary"
    assert "google_images" in links, "Should contain Google Images link"
    assert "bing" in links, "Should contain Bing link"
    assert "yandex" in links, "Should contain Yandex link"
    assert "tineye" in links, "Should contain TinEye link"
    
    print(f"\n[+] Generated {len(links)} search engine links:")
    for engine, url in links.items():
        print(f"\n    [{engine.upper()}]")
        print(f"    {url}")
        
        # Verify URLs are valid
        assert url.startswith("http"), f"{engine} link should start with http"
        assert test_url.replace("https://", "").replace("http://", "") in url or \
               "example.com" in url or \
               "%3A%2F%2F" in url, f"{engine} link should contain the image URL"
    
    print("\n[PASS] Reverse image link generation test passed!")


def test_generate_reverse_links_special_chars():
    """Test with URLs containing special characters"""
    print("\n" + "=" * 60)
    print("Testing Reverse Image Search - Special Characters")
    print("=" * 60)
    
    test_url = "https://example.com/images/photo with spaces & symbols.jpg"
    
    print(f"\n[*] Testing with special characters: {test_url}")
    links = generate_reverse_links(test_url)
    
    # Verify all links are generated
    assert len(links) == 5, "Should generate 5 search engine links"
    
    # Verify URLs are properly encoded
    for engine, url in links.items():
        assert " " not in url, f"{engine} link should not contain spaces"
        print(f"    [OK] {engine}: URL properly encoded")
    
    print("\n[PASS] Special characters test passed!")


def test_generate_reverse_links_https():
    """Test with HTTPS URLs"""
    print("\n" + "=" * 60)
    print("Testing Reverse Image Search - HTTPS")
    print("=" * 60)
    
    test_url = "https://secure.example.com/image.png"
    
    print(f"\n[*] Testing with HTTPS URL: {test_url}")
    links = generate_reverse_links(test_url)
    
    assert isinstance(links, dict), "Should return dictionary"
    assert len(links) > 0, "Should generate links"
    
    print(f"\n[+] Successfully generated {len(links)} links for HTTPS URL")
    print("\n[PASS] HTTPS test passed!")


if __name__ == "__main__":
    try:
        test_generate_reverse_links()
        test_generate_reverse_links_special_chars()
        test_generate_reverse_links_https()
        
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
