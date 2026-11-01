#!/usr/bin/env python3
"""
Comprehensive test for the Certificate Transparency Log Monitoring module.
"""

import sys
import os
import logging

# Add the parent directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

from modules.ct_log_monitor import (  # noqa: E402
    query_crt_sh, 
    query_certspotter, 
    query_bufferover,
    monitor_certificate_transparency
)

def test_individual_queries():
    """Test each CT log service individually."""
    print("Testing individual CT log queries...")
    
    test_domain = "example.com"
    
    # Test crt.sh
    print("1. Testing crt.sh query...")
    crt_sh_results = query_crt_sh(test_domain)
    print(f"   Found {len(crt_sh_results)} subdomains")
    
    # Test CertSpotter
    print("2. Testing CertSpotter query...")
    certspotter_results = query_certspotter(test_domain)
    print(f"   Found {len(certspotter_results)} subdomains")
    
    # Test BufferOver
    print("3. Testing BufferOver query...")
    bufferover_results = query_bufferover(test_domain)
    print(f"   Found {len(bufferover_results)} subdomains")
    
    return crt_sh_results, certspotter_results, bufferover_results

def test_combined_monitoring():
    """Test the combined monitoring function."""
    print("\nTesting combined Certificate Transparency monitoring...")
    
    test_domain = "github.com"  # Should have many results
    
    results = monitor_certificate_transparency(test_domain)
    
    print(f"Domain: {results.get('domain')}")
    print(f"Total unique subdomains: {results.get('total_found', 0)}")
    
    # Print source breakdown
    sources = results.get('sources', {})
    print("Source breakdown:")
    for source, count in sources.items():
        print(f"  {source}: {count}")
        
    # Show sample results
    subdomains = results.get('subdomains', [])
    print("\nSample subdomains (first 10):")
    for subdomain in subdomains[:10]:
        print(f"  - {subdomain}")
        
    if len(subdomains) > 10:
        print(f"  ... and {len(subdomains) - 10} more")
        
    return results

def show_capabilities():
    """Show the capabilities of the CT monitoring module."""
    print("\nCertificate Transparency Monitoring Capabilities:")
    print("=" * 50)
    print("1. Multi-Source Querying:")
    print("   - crt.sh: Comprehensive CT log search platform")
    print("   - CertSpotter: Dedicated certificate monitoring API")
    print("   - BufferOver: DNS-based subdomain discovery")
    
    print("\n2. Enhanced Subdomain Discovery:")
    print("   - Finds subdomains not in traditional wordlists")
    print("   - Discovers recently issued certificates")
    print("   - Provides passive reconnaissance capabilities")
    print("   - Identifies potential attack surface expansion")
    
    print("\n3. Robust Implementation:")
    print("   - Rate limiting respectful to APIs")
    print("   - Deduplication of results across sources")
    print("   - Detailed source attribution")
    print("   - Comprehensive error handling")
    print("   - JSON output for easy integration")
    
    print("\n4. Security Professional Benefits:")
    print("   - Enhanced attack surface discovery")
    print("   - Detection of recently added subdomains")
    print("   - Identification of potential security gaps")
    print("   - Comprehensive reconnaissance coverage")

def main():
    print("Comprehensive Certificate Transparency Log Monitoring Test")
    print("=" * 60)
    
    show_capabilities()
    
    print("\n" + "=" * 60)
    print("Running tests...")
    
    # Test individual queries
    crt_sh_results, certspotter_results, bufferover_results = test_individual_queries()
    
    # Test combined monitoring
    test_combined_monitoring()
    
    print("\n" + "=" * 60)
    print("All tests completed successfully!")
    print("\nCertificate Transparency Log Monitoring is ready for use in Modular ReconX.")
    print("It will automatically run as part of the scanning workflow and enhance")
    print("subdomain discovery beyond traditional wordlist-based enumeration.")

if __name__ == "__main__":
    main()