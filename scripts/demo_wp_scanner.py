#!/usr/bin/env python3
"""
Demo script to show how the enhanced WordPress scanner works.
"""

import sys
import os

# Add the parent directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.wp_scanner import (
    _extract_plugins_from_html,
    _extract_version_from_css,
    _extract_version_from_js,
    _extract_version_from_readme
)

def main():
    print("WordPress Scanner Enhanced Demo")
    print("=" * 40)
    
    # Demo plugin detection methods
    print("\n1. Plugin Detection Methods:")
    print("The enhanced scanner uses multiple techniques:")
    print("  - CSS/JS file detection in wp-content/plugins/")
    print("  - readme.txt file analysis")
    print("  - HTML source code signature scanning")
    print("  - WordPress REST API (when available)")
    print("  - Meta tag and comment analysis")
    
    # Demo version extraction functions
    print("\n2. Version Extraction Capabilities:")
    
    # CSS version extraction demo
    css_sample = """
    /*!
     * Plugin Name: Sample Plugin
     * Version: 1.2.3
     * Description: A sample plugin
     */
    """
    version = _extract_version_from_css(css_sample)
    print(f"  From CSS: '{version}'")
    
    # JS version extraction demo
    js_sample = """
    var plugin = {
        version: "2.1.5",
        name: "Sample Plugin"
    };
    """
    version = _extract_version_from_js(js_sample)
    print(f"  From JS: '{version}'")
    
    # Readme version extraction demo
    readme_sample = """
    === Sample Plugin ===
    Contributors: author
    Tags: sample
    Requires at least: 4.0
    Tested up to: 5.8
    Stable tag: 3.0.1
    """
    version = _extract_version_from_readme(readme_sample)
    print(f"  From readme.txt: '{version}'")
    
    # HTML plugin extraction demo
    html_sample = """
    <html>
    <head>
        <script src='https://example.com/wp-content/plugins/contact-form-7/js/scripts.js'></script>
        <link rel='stylesheet' href='https://example.com/wp-content/plugins/woocommerce/assets/css/woocommerce.css' />
    </head>
    </html>
    """
    plugins = _extract_plugins_from_html(html_sample)
    print(f"  From HTML: {len(plugins)} plugins detected")
    for plugin in plugins:
        print(f"    - {plugin['slug']}")
    
    # Demo vulnerability checking
    print("\n3. Vulnerability Checking Demo:")
    
    print("Vulnerability checking requires WPSCAN_API_KEY to be set in .env")
    print("When configured, it will check each plugin against WPScan database")
    print("and compare versions to identify potential vulnerabilities.")
    
    print("\n4. Enhanced Features:")
    print("  - Checks 30+ common WordPress plugins")
    print("  - Multiple detection methods for better accuracy")
    print("  - Version extraction from multiple file types")
    print("  - REST API integration when available")
    print("  - Comprehensive vulnerability assessment")
    print("  - Detailed reporting with fix versions")

if __name__ == "__main__":
    main()