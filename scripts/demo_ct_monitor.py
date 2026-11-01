#!/usr/bin/env python3
"""
Demo script for the Certificate Transparency Log Monitoring module.
"""

import sys
import os

# Add the parent directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def main():
    print("Certificate Transparency Log Monitoring Demo")
    print("=" * 50)
    
    print("\n1. What is Certificate Transparency?")
    print("   Certificate Transparency (CT) is an open framework that enables")
    print("   the monitoring of certificates issued by Certificate Authorities.")
    print("   It helps detect mistakenly or maliciously issued certificates.")
    
    print("\n2. How CT Monitoring Enhances Subdomain Discovery:")
    print("   - Finds subdomains that may not be in wordlists")
    print("   - Discovers subdomains from recently issued certificates")
    print("   - Provides passive reconnaissance capabilities")
    print("   - Identifies potential attack surface expansion")
    
    print("\n3. Data Sources:")
    print("   - crt.sh: Popular CT log search platform")
    print("   - CertSpotter: API for certificate monitoring")
    print("   - BufferOver: DNS-based subdomain discovery")
    
    print("\n4. Key Features of Our Implementation:")
    print("   - Multi-source querying for comprehensive coverage")
    print("   - Rate limiting respectful to APIs")
    print("   - Deduplication of results")
    print("   - Detailed source attribution")
    print("   - Error handling and logging")
    
    print("\n5. Integration with Modular ReconX:")
    print("   - Automatically runs as part of the scanning workflow")
    print("   - Combines results with wordlist-based enumeration")
    print("   - Enhances overall subdomain discovery capabilities")
    print("   - Provides additional passive reconnaissance data")
    
    print("\n6. Running a Test:")
    print("   To test the CT monitoring:")
    print("   $ python test_ct_monitor.py")
    print("\n   This will query multiple CT log services and return")
    print("   discovered subdomains for a test domain.")
    
    print("\n7. Benefits for Security Professionals:")
    print("   - Enhanced attack surface discovery")
    print("   - Detection of recently added subdomains")
    print("   - Identification of potential security gaps")
    print("   - Comprehensive reconnaissance coverage")

if __name__ == "__main__":
    main()