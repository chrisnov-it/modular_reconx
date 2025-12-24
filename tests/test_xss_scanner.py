#!/usr/bin/env python3
"""
Test script for XSS Scanner module
"""

import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from modules.xss_scanner import scan_xss

def test_xss_scanner():
    """Test the XSS Scanner module with a sample URL"""
    test_url = "https://httpbin.org/get?test=value"

    print("Testing XSS Scanner module...")
    print(f"Target: {test_url}")
    print("=" * 50)

    # Test XSS scanning
    print("\n1. Testing XSS Scanner...")
    try:
        xss_results = scan_xss(test_url)
        print("   [+] XSS scanning completed successfully")

        # Extract key information
        vulnerabilities = xss_results.get('vulnerabilities', [])
        scanned_params = xss_results.get('scanned_params', [])

        print(f"   Parameters scanned: {len(scanned_params)}")
        print(f"   Vulnerabilities found: {len(vulnerabilities)}")

        if vulnerabilities:
            for vuln in vulnerabilities:
                print(f"     - Parameter '{vuln['parameter']}' vulnerable: {', '.join(vuln['context'])}")

    except Exception as e:
        print(f"   [-] XSS scanning failed: {e}")

    print("\n" + "=" * 50)
    print("XSS Scanner module test completed!")

if __name__ == "__main__":
    test_xss_scanner()