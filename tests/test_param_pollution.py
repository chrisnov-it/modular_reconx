#!/usr/bin/env python3
"""
Test script for HTTP Parameter Pollution module
"""

import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from modules.param_pollution import comprehensive_parameter_pollution_analysis

def test_param_pollution_module():
    """Test the HTTP Parameter Pollution module with a sample URL"""
    test_url = "https://httpbin.org/get?test=original"
    
    print("Testing HTTP Parameter Pollution module...")
    print(f"Target: {test_url}")
    print("=" * 50)
    
    # Test parameter pollution analysis
    print("\n1. Testing Parameter Pollution Analysis...")
    try:
        pollution_results = comprehensive_parameter_pollution_analysis(test_url)
        print("   [+] Parameter pollution analysis completed successfully")
        
        # Extract key information
        pollution_detection = pollution_results.get('pollution_detection', {})
        vulnerable = pollution_detection.get('vulnerability_assessment', {}).get('vulnerable', False)
        risk_level = pollution_detection.get('vulnerability_assessment', {}).get('risk_level', 'unknown')
        tests_performed = len(pollution_detection.get('pollution_tests', []))
        
        print(f"   Vulnerable: {vulnerable}")
        print(f"   Risk Level: {risk_level}")
        print(f"   Tests performed: {tests_performed}")
        
        if vulnerable:
            issues = pollution_detection.get('vulnerability_assessment', {}).get('issues', [])
            print(f"   Issues found: {len(issues)}")
            for issue in issues:
                print(f"     - {issue}")
        
    except Exception as e:
        print(f"   [-] Parameter pollution analysis failed: {e}")
    
    print("\n" + "=" * 50)
    print("HTTP Parameter Pollution module test completed!")

if __name__ == "__main__":
    test_param_pollution_module()