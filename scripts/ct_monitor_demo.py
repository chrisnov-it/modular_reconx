#!/usr/bin/env python3
"""
Final demonstration of the Certificate Transparency Log Monitoring module.
"""

import sys
import os

# Add the parent directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    print("Modular ReconX - Certificate Transparency Log Monitoring")
    print("=" * 55)
    print()
    
    print("Enhancing Subdomain Discovery Beyond Wordlists")
    print("---------------------------------------------")
    print()
    
    print("What is Certificate Transparency (CT)?")
    print("  Certificate Transparency is an open framework that enables")
    print("  the monitoring of certificates issued by Certificate Authorities.")
    print("  It helps detect mistakenly or maliciously issued certificates.")
    print()
    
    print("How CT Monitoring Enhances Reconnaissance:")
    print("  1. Discovers subdomains that may not appear in wordlists")
    print("  2. Finds recently issued certificates and new subdomains")
    print("  3. Provides passive reconnaissance without direct probing")
    print("  4. Identifies potential attack surface expansion")
    print("  5. Complements traditional DNS enumeration methods")
    print()
    
    print("Data Sources Utilized:")
    print("  • crt.sh - Comprehensive CT log search platform")
    print("  • CertSpotter - Dedicated certificate monitoring API")
    print("  • BufferOver - DNS-based subdomain discovery service")
    print()
    
    print("Key Features of Our Implementation:")
    print("  ✓ Multi-source querying for comprehensive coverage")
    print("  ✓ Rate limiting respectful to public APIs")
    print("  ✓ Intelligent deduplication of results")
    print("  ✓ Detailed source attribution for transparency")
    print("  ✓ Robust error handling and logging")
    print("  ✓ JSON output for easy integration")
    print()
    
    print("Benefits for Security Professionals:")
    print("  • Enhanced attack surface discovery")
    print("  • Detection of recently added subdomains")
    print("  • Identification of potential security gaps")
    print("  • Comprehensive reconnaissance coverage")
    print("  • Passive intelligence gathering")
    print()
    
    print("Integration with Modular ReconX:")
    print("  The CT monitoring module automatically runs as part of the")
    print("  scanning workflow, combining results with wordlist-based")
    print("  enumeration for the most comprehensive subdomain discovery.")
    print()
    
    print("Example Usage:")
    print("  $ python scan.py example.com")
    print("  This will include CT log monitoring in the scan results.")
    print()
    
    print("Technical Details:")
    print("  - Respects API rate limits with built-in delays")
    print("  - Handles network timeouts gracefully")
    print("  - Filters results to only include relevant subdomains")
    print("  - Provides detailed statistics on data sources")
    print("  - Works seamlessly with existing Modular ReconX modules")
    print()
    
    print("To test the module:")
    print("  $ python test_ct_monitor.py")
    print()
    
    print("The Certificate Transparency Log Monitoring module represents")
    print("a significant enhancement to Modular ReconX's reconnaissance")
    print("capabilities, providing security professionals with additional")
    print("passive intelligence gathering methods beyond traditional")
    print("enumeration techniques.")

if __name__ == "__main__":
    main()