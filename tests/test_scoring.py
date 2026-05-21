#!/usr/bin/env python3
"""
Test script for the enhanced scoring module
"""

import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from modules.scoring import VulnerabilityScorer

def test_scoring_module():
    """Test the scoring module with mock data"""
    print("Testing Enhanced Scoring Module...")
    print("=" * 50)

    # Create mock bug hunt results
    mock_results = {
        "js_analysis": {
            "js_files": [
                {
                    "url": "https://example.com/app.js",
                    "security_issues": ["Direct innerHTML assignment detected"],
                    "vulnerable_patterns": []
                }
            ]
        },
        "security_headers_analysis": {
            "security_headers": {
                "security_analysis": {
                    "missing_headers": {
                        "content-security-policy": {"description": "CSP header"},
                        "strict-transport-security": {"description": "HSTS header"}
                    },
                    "present_headers": {},
                    "deprecated_headers": {
                        "server": {"value": "Apache/2.4.0", "reason": "Info disclosure"}
                    }
                }
            }
        },
        "clickjacking_analysis": {
            "protection_analysis": {
                "vulnerability_assessment": {
                    "vulnerable": True,
                    "risk_level": "high"
                }
            }
        }
    }

    # Test scoring
    scorer = VulnerabilityScorer()
    scoring_results = scorer.analyze_bug_hunt_results(mock_results)

    print("[+] Scoring analysis completed successfully")
    print(f"   - Overall Risk Score: {scoring_results['overall_score']:.1f}/100")
    print(f"   - Risk Level: {scoring_results['risk_level']}")
    print(f"   - Total Findings: {len(scoring_results['findings'])}")

    # Verify expected findings
    expected_findings = ["DOM XSS Vulnerability", "Missing Content Security Policy", "Missing HSTS Header", "Clickjacking Vulnerability"]
    found_titles = [f["title"] for f in scoring_results["findings"]]

    for expected in expected_findings:
        if expected in found_titles:
            print(f"   [+] Found expected finding: {expected}")
        else:
            print(f"   [-] Missing expected finding: {expected}")

    # Check risk distribution
    print("\nRisk Distribution:")
    for severity, count in scoring_results['severity_distribution'].items():
        if count > 0:
            print(f"   - {severity}: {count}")

    print("\n" + "=" * 50)
    print("Enhanced Scoring Module test completed!")

if __name__ == "__main__":
    test_scoring_module()