#!/usr/bin/env python3
"""
Test script for the Certificate Transparency Log Monitoring module.
"""

import sys
import os
import logging

# Add the parent directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

from modules.ct_log_monitor import monitor_certificate_transparency  # noqa: E402

def main():
    # Test with a known domain
    test_domain = "github.com"  # This should have many certificates
    
    print(f"Testing Certificate Transparency Log Monitoring on {test_domain}")
    print("=" * 60)
    
    try:
        results = monitor_certificate_transparency(test_domain)
        
        print(f"\nResults for {test_domain}:")
        print(f"Total unique subdomains found: {results.get('total_found', 0)}")
        
        # Print sources breakdown
        sources = results.get('sources', {})
        print("\nSources breakdown:")
        for source, count in sources.items():
            print(f"  {source}: {count}")
        
        # Print some of the found subdomains
        subdomains = results.get('subdomains', [])
        print("\nSample of found subdomains (first 20):")
        for subdomain in subdomains[:20]:
            print(f"  - {subdomain}")
            
        if len(subdomains) > 20:
            print(f"  ... and {len(subdomains) - 20} more")
            
        # Save results to a file for review
        import json
        output_file = f"ct_results_{test_domain.replace('.', '_')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nFull results saved to {output_file}")
        
    except Exception as e:
        print(f"Error during CT monitoring: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()