#!/usr/bin/env python3
"""
Test script for the enhanced output and reporting features
"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.modules.reporting import save_report

def test_enhanced_output_formats():
    """Test the enhanced output and reporting features"""
    print("Testing enhanced output and reporting features...")
    
    # Sample data for testing
    sample_data = {
        "domain": "example.com",
        "ip_address": "93.184.216.34",
        "whois": {
            "domain_name": "example.com",
            "registrar": "Example Registrar",
            "creation_date": "1995-08-14 04:00:00",
            "expiration_date": "2025-08-13 04:00:00"
        },
        "dns": {
            "A": ["93.184.216.34"],
            "MX": ["10 mail.example.com"]
        },
        "subdomains": {
            "found": [
                {
                    "subdomain": "www.example.com",
                    "ips": ["93.184.216.34"],
                    "cname": None
                },
                {
                    "subdomain": "mail.example.com",
                    "ips": ["93.184.216.35"],
                    "cname": None
                }
            ]
        },
        "open_ports": {
            "open_ports": {
                "80": "HTTP",
                "443": "HTTPS"
            }
        },
        "vulnerabilities": {
            "apache/2.4.49": [
                {
                    "id": "CVE-2021-41773",
                    "title": "Apache HTTP Server 2.4.49 - Path Traversal",
                    "cvss_score": 9.8,
                    "source": "Local DB"
                }
            ]
        },
        "exploits": {
            "apache/2.4.49": [
                {
                    "id": "EXP-001",
                    "title": "Apache HTTP Server 2.4.49 - Path Traversal",
                    "type": "remote",
                    "platform": "linux",
                    "source": "Local Exploit DB"
                }
            ]
        }
    }
    
    # Test JSON output
    print("\n1. Testing JSON output...")
    try:
        json_file = save_report(sample_data, "json")
        print(f"  [+] JSON report saved to: {json_file}")
    except Exception as e:
        print(f"  [-] JSON output failed: {e}")
    
    # Test text output
    print("\n2. Testing text output...")
    try:
        txt_file = save_report(sample_data, "txt")
        print(f"  [+] Text report saved to: {txt_file}")
    except Exception as e:
        print(f"  [-] Text output failed: {e}")
    
    # Test HTML output
    print("\n3. Testing HTML output...")
    try:
        html_file = save_report(sample_data, "html")
        print(f"  [+] HTML report saved to: {html_file}")
    except Exception as e:
        print(f"  [-] HTML output failed: {e}")
    
    # Test CSV output
    print("\n4. Testing CSV output...")
    try:
        csv_file = save_report(sample_data, "csv")
        print(f"  [+] CSV report saved to: {csv_file}")
    except Exception as e:
        print(f"  [-] CSV output failed: {e}")
    
    print("\nEnhanced output and reporting tests completed!")

if __name__ == "__main__":
    test_enhanced_output_formats()
