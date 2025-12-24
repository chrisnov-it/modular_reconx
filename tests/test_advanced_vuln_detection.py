#!/usr/bin/env python3
"""
Test script for advanced vulnerability detection module
"""

import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from modules.advanced_vuln_detection import run_advanced_vulnerability_detection

def test_advanced_vuln_detection():
    """Test the advanced vulnerability detection module"""
    print("Testing Advanced Vulnerability Detection Module...")
    print("=" * 60)

    # Test with httpbin.org (safe test target)
    test_url = "https://httpbin.org"

    print(f"Testing with: {test_url}")
    print("-" * 40)

    try:
        results = run_advanced_vulnerability_detection(test_url)

        print("[+] Advanced detection completed successfully")
        print(f"   - Total checks performed: {results['summary']['total_checks']}")
        print(f"   - Vulnerabilities found: {results['summary']['vulnerabilities_found']}")
        print(f"   - Critical findings: {results['summary']['critical_findings']}")
        print(f"   - High findings: {results['summary']['high_findings']}")

        # Show details of each check
        print("\nCheck Results:")
        for check_name, check_result in results.items():
            if check_name != "summary" and isinstance(check_result, dict):
                if "findings" in check_result:
                    print(f"   - {check_name}: {len(check_result['findings'])} findings")
                    if check_result["findings"]:
                        for finding in check_result["findings"][:2]:  # Show first 2
                            print(f"     * {finding['severity']}: {finding['title']}")
                elif "vulnerabilities_found" in check_result:
                    print(f"   - {check_name}: {check_result['vulnerabilities_found']} vulnerabilities")

        # Show sample findings
        all_findings = []
        for check_result in results.values():
            if isinstance(check_result, dict) and "findings" in check_result:
                all_findings.extend(check_result["findings"])

        if all_findings:
            print(f"\nSample Findings (Total: {len(all_findings)}):")
            for i, finding in enumerate(all_findings[:3]):  # Show first 3
                print(f"   {i+1}. [{finding['severity']}] {finding['title']}")
                print(f"      {finding['description']}")
                if finding.get('recommendations'):
                    print(f"      Recommendation: {finding['recommendations'][0]}")

    except Exception as e:
        print(f"[-] Advanced detection test failed: {e}")
        import traceback
        traceback.print_exc()

    print("\n" + "=" * 60)
    print("Advanced Vulnerability Detection test completed!")

if __name__ == "__main__":
    test_advanced_vuln_detection()