#!/usr/bin/env python3
"""
Test script for the enhanced WordPress scanner.
"""

import sys
import os

# Add the parent directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.wp_scanner import scan_wordpress_site

def main():
    # Test with a known WordPress site
    test_url = "https://wordpress.org"  # This is a WordPress site
    
    print(f"Testing WordPress scanner on {test_url}")
    print("=" * 50)
    
    try:
        results = scan_wordpress_site(test_url)
        
        print("\nScan Results:")
        print(f"Total plugins detected: {results.get('scan_summary', {}).get('total_plugins_detected', 0)}")
        print(f"Vulnerable plugins: {results.get('scan_summary', {}).get('vulnerable_plugins', 0)}")
        print(f"Total vulnerabilities: {results.get('scan_summary', {}).get('total_vulnerabilities', 0)}")
        
        # Print detected plugins
        print("\nDetected Plugins:")
        for plugin in results.get('detected_plugins', []):
            print(f"  - {plugin['slug']} (v{plugin['version']})")
            
        # Print vulnerabilities
        print("\nVulnerabilities:")
        for plugin_slug, vuln_data in results.get('vulnerabilities', {}).items():
            if 'vulnerabilities' in vuln_data:
                print(f"  {plugin_slug}:")
                for vuln in vuln_data['vulnerabilities']:
                    print(f"    - {vuln['title']}")
                    if vuln['fixed_in'] != "N/A":
                        print(f"      Fixed in: {vuln['fixed_in']}")
            elif 'note' in vuln_data:
                print(f"  {plugin_slug}: {vuln_data['note']}")
            elif 'error' in vuln_data:
                print(f"  {plugin_slug}: ERROR - {vuln_data['error']}")
                
    except Exception as e:
        print(f"Error during scan: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()