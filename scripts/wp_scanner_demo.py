#!/usr/bin/env python3
"""
Real-world demonstration of the enhanced WordPress scanner.
This script shows how to use the scanner with actual websites.
"""

import sys
import os

# Add the parent directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.wp_scanner import scan_wordpress_site

def demo_with_wordpress_sites():
    """Demonstrate scanning real WordPress sites."""
    print("WordPress Scanner Real-World Demo")
    print("=" * 40)
    
    # List of known WordPress sites for demonstration
    test_sites = [
        "https://wordpress.org",  # Official WordPress site
        "https://ma.tt",          # Matt Mullenweg's site (WordPress co-founder)
    ]
    
    print("Note: Actual plugin detection depends on the target site's configuration.")
    print("Some sites may block direct access to plugin files for security reasons.")
    print()
    
    for site in test_sites:
        print(f"Scanning {site}...")
        try:
            results = scan_wordpress_site(site)
            
            print(f"  Plugins detected: {results.get('scan_summary', {}).get('total_plugins_detected', 0)}")
            print(f"  Vulnerable plugins: {results.get('scan_summary', {}).get('vulnerable_plugins', 0)}")
            print(f"  Total vulnerabilities: {results.get('scan_summary', {}).get('total_vulnerabilities', 0)}")
            
            # Show detected plugins
            plugins = results.get('detected_plugins', [])
            if plugins:
                print("  Detected plugins:")
                for plugin in plugins[:5]:  # Show first 5
                    print(f"    - {plugin['slug']} (v{plugin['version']})")
                if len(plugins) > 5:
                    print(f"    ... and {len(plugins) - 5} more")
            else:
                print("  No plugins detected (this is normal for some sites)")
            
        except Exception as e:
            print(f"  Error scanning {site}: {e}")
        
        print()

def show_capabilities():
    """Show the capabilities of the enhanced scanner."""
    print("Enhanced WordPress Scanner Capabilities:")
    print("=" * 40)
    print("1. Multiple Detection Methods:")
    print("   - CSS/JS file detection in wp-content/plugins/")
    print("   - readme.txt file analysis")
    print("   - HTML source code signature scanning")
    print("   - WordPress REST API integration (when available)")
    print("   - Meta tag and comment analysis")
    print()
    
    print("2. Comprehensive Plugin Coverage:")
    print("   - Checks 30+ most common WordPress plugins")
    print("   - Automatic version detection when possible")
    print("   - Works with various plugin directory structures")
    print()
    
    print("3. Vulnerability Assessment:")
    print("   - Integrates with WPScan API for vulnerability data")
    print("   - Version comparison to identify vulnerable plugins")
    print("   - Detailed vulnerability information with fix versions")
    print()
    
    print("4. Robust Error Handling:")
    print("   - Graceful degradation when methods fail")
    print("   - Clear error messages for troubleshooting")
    print("   - Timeout handling for unresponsive sites")
    print()
    
    print("5. Detailed Reporting:")
    print("   - Summary statistics")
    print("   - Per-plugin vulnerability details")
    print("   - Reference links for further information")

def main():
    print("Modular ReconX - Enhanced WordPress Scanner")
    print("===========================================")
    print()
    
    show_capabilities()
    print()
    
    print("To use the scanner with your own sites:")
    print("1. Ensure you have permission to scan the target site")
    print("2. Set WPSCAN_API_KEY in your .env file for vulnerability checks")
    print("3. Run: python scan.py example.com (for full OSINT scan)")
    print("   or use the WordPress scanner directly as shown in this demo")
    print()
    
    # Uncomment the following lines to run actual scans (requires internet connection)
    # print("Running demonstration scans...")
    # demo_with_wordpress_sites()

if __name__ == "__main__":
    main()