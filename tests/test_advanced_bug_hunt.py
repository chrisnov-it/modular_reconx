#!/usr/bin/env python3
"""
Test script for advanced bug hunting modules
"""

import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from modules.cors_checker import comprehensive_cors_analysis
from modules.cookie_analysis import comprehensive_cookie_analysis
from modules.clickjacking_checker import comprehensive_clickjacking_analysis

def test_advanced_bug_hunt_modules():
    """Test all advanced bug hunting modules with a sample URL"""
    test_url = "https://httpbin.org"
    
    print("Testing advanced bug hunting modules...")
    print(f"Target: {test_url}")
    print("=" * 50)
    
    # Test CORS analysis
    print("\n1. Testing CORS Analysis...")
    try:
        cors_results = comprehensive_cors_analysis(test_url)
        print("   [+] CORS analysis completed successfully")
        risk_level = cors_results.get('cors_analysis', {}).get('risk_level', 'unknown')
        print(f"   Risk Level: {risk_level}")
        misconfigs = len(cors_results.get('cors_analysis', {}).get('misconfigurations', []))
        print(f"   Misconfigurations found: {misconfigs}")
    except Exception as e:
        print(f"   [-] CORS analysis failed: {e}")
    
    # Test cookie analysis
    print("\n2. Testing Cookie Analysis...")
    try:
        cookie_results = comprehensive_cookie_analysis(test_url)
        print("   [+] Cookie analysis completed successfully")
        cookies_found = len(cookie_results.get('cookie_analysis', {}).get('cookies', []))
        print(f"   Cookies found: {cookies_found}")
        risk_score = cookie_results.get('cookie_analysis', {}).get('risk_score', 0)
        print(f"   Risk Score: {risk_score}")
    except Exception as e:
        print(f"   [-] Cookie analysis failed: {e}")
    
    # Test clickjacking analysis
    print("\n3. Testing Clickjacking Analysis...")
    try:
        clickjacking_results = comprehensive_clickjacking_analysis(test_url)
        print("   [+] Clickjacking analysis completed successfully")
        vulnerable = clickjacking_results.get('protection_analysis', {}).get('vulnerability_assessment', {}).get('vulnerable', False)
        risk_level = clickjacking_results.get('protection_analysis', {}).get('vulnerability_assessment', {}).get('risk_level', 'unknown')
        print(f"   Vulnerable: {vulnerable}")
        print(f"   Risk Level: {risk_level}")
    except Exception as e:
        print(f"   [-] Clickjacking analysis failed: {e}")
    
    print("\n" + "=" * 50)
    print("Advanced bug hunting module tests completed!")

if __name__ == "__main__":
    test_advanced_bug_hunt_modules()