#!/usr/bin/env python3
"""
Test script for bug hunting modules
"""

import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from modules.param_analysis import comprehensive_param_analysis
from modules.js_analysis import comprehensive_js_analysis
from modules.api_discovery import comprehensive_api_discovery
from modules.security_headers import comprehensive_security_analysis
from modules.form_analysis import comprehensive_form_analysis

def test_bug_hunt_modules():
    """Test all bug hunting modules with a sample URL"""
    test_url = "https://httpbin.org"
    
    print("Testing bug hunting modules...")
    print(f"Target: {test_url}")
    print("=" * 50)
    
    # Test parameter analysis
    print("\n1. Testing Parameter Analysis...")
    try:
        param_results = comprehensive_param_analysis(test_url)
        print("   [+] Parameter analysis completed successfully")
        print(f"   Risk Score: {param_results.get('overall_risk_score', 0)}")
    except Exception as e:
        print(f"   [-] Parameter analysis failed: {e}")
    
    # Test JavaScript analysis
    print("\n2. Testing JavaScript Analysis...")
    try:
        js_results = comprehensive_js_analysis(test_url)
        print("   [+] JavaScript analysis completed successfully")
        print(f"   Files analyzed: {js_results.get('total_files', 0)}")
        print(f"   Files with issues: {js_results.get('files_with_issues', 0)}")
    except Exception as e:
        print(f"   [-] JavaScript analysis failed: {e}")
    
    # Test API discovery
    print("\n3. Testing API Discovery...")
    try:
        api_results = comprehensive_api_discovery(test_url)
        print("   [+] API discovery completed successfully")
        print(f"   Endpoints found: {api_results.get('total_endpoints', 0)}")
    except Exception as e:
        print(f"   [-] API discovery failed: {e}")
    
    # Test security headers analysis
    print("\n4. Testing Security Headers Analysis...")
    try:
        sec_results = comprehensive_security_analysis(test_url)
        print("   [+] Security headers analysis completed successfully")
        score = sec_results.get('security_headers', {}).get('security_analysis', {}).get('security_score', 0)
        print(f"   Security Score: {score}/100")
    except Exception as e:
        print(f"   [-] Security headers analysis failed: {e}")
    
    # Test form analysis
    print("\n5. Testing Form Analysis...")
    try:
        form_results = comprehensive_form_analysis(test_url)
        print("   [+] Form analysis completed successfully")
        total_forms = form_results.get('form_analysis', {}).get('total_forms', 0)
        vulnerable_forms = form_results.get('form_analysis', {}).get('vulnerable_forms', 0)
        print(f"   Total forms: {total_forms}")
        print(f"   Vulnerable forms: {vulnerable_forms}")
    except Exception as e:
        print(f"   ✗ Form analysis failed: {e}")
    
    print("\n" + "=" * 50)
    print("Bug hunting module tests completed!")

if __name__ == "__main__":
    test_bug_hunt_modules()