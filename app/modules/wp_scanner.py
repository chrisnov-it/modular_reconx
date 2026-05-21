# Inside modules/wp_scanner.py

import os
import logging
import re
from typing import Dict, List, Any
from urllib.parse import urljoin
from .http_client import get_http_client

logger = logging.getLogger(__name__)


def check_plugin_vulnerabilities(plugin_slug: str, version: str) -> dict:
    """
    Check vulnerabilities for a WordPress plugin based on its version using the WPScan API.
    """
    api_key = os.getenv("WPSCAN_API_KEY")
    if not api_key:
        return {"error": "WPSCAN_API_KEY not set."}

    url = f"https://wpscan.com/api/v3/plugins/{plugin_slug}"
    headers = {"Authorization": f"Token token={api_key}"}

    try:
        response = get_http_client().get(url, headers=headers, timeout=15)
        if response.status_code == 404:
            return {
                "note": f"Plugin '{plugin_slug}' not found in WPScan database."
            }
        response.raise_for_status()

        data = response.json()
        plugin_data = data.get(plugin_slug, {})

        found_vulns = []
        # Loop through all known vulnerabilities for this plugin
        for vuln in plugin_data.get("vulnerabilities", []):
            # Check if the installed version is affected by this vulnerability
            fixed_in = vuln.get("fixed_in", "")
            
            # If there is no version fix information, or the tested version is lower than the fix version
            is_vulnerable = False
            if not fixed_in:
                # If there is no fixed_in information, assume it's vulnerable
                is_vulnerable = True
            else:
                # Simple version comparison (in a real implementation, use a version comparison library)
                if version == "0" or _is_version_less_than(version, fixed_in):
                    is_vulnerable = True
            
            if is_vulnerable:
                found_vulns.append(
                    {
                        "title": vuln.get("title"),
                        "fixed_in": fixed_in,
                        "references": vuln.get("references", {}).get("url", []),
                    }
                )

        if not found_vulns:
            return {
                "note": f"No public vulnerabilities known for plugin '{plugin_slug}' version {version}."
            }

        return {"vulnerabilities": found_vulns}

    except Exception as e:
        return {"error": f"API request to WPScan failed: {e}"}


def _is_version_less_than(version1: str, version2: str) -> bool:
    """
    Simple version comparison to determine if version1 < version2.
    This is a simple implementation and may not be accurate for all version formats.
    """
    try:
        # Split version strings and convert to integers for comparison
        v1_parts = [int(x) for x in version1.split('.') if x.isdigit()]
        v2_parts = [int(x) for x in version2.split('.') if x.isdigit()]
        
        # Compare version parts
        for i in range(min(len(v1_parts), len(v2_parts))):
            if v1_parts[i] < v2_parts[i]:
                return True
            elif v1_parts[i] > v2_parts[i]:
                return False
        
        # If all compared parts are equal, the version with fewer parts is smaller
        return len(v1_parts) < len(v2_parts)
    except:  # noqa: E722
        # If comparison fails, assume it's vulnerable
        return True


def detect_installed_plugins(base_url: str) -> List[Dict[str, str]]:
    """
    Detect installed WordPress plugins using various methods.
    
    Args:
        base_url: The base URL of the WordPress site
        
    Returns:
        List of dictionaries containing plugin slug and version
    """
    detected_plugins = []
    checked_urls = set()  # To avoid duplicate checks
    
    # Method 1: Check common plugin files
    common_plugins = [
        "contact-form-7", "woocommerce", "jetpack", "wordpress-seo", "akismet",
        "wpforms", "elementor", "updraftplus", "wordfence", "really-simple-ssl",
        "duplicate-post", "google-site-kit", "mailchimp-for-wp", "classic-editor",
        "all-in-one-wp-migration", "wp-super-cache", "w3-total-cache", "nextgen-gallery",
        "revslider", "layer-slider", "bbpress", "buddypress", "wp-statistics",
        "google-analytics-for-wordpress", "wp-multibyte-patch", "regenerate-thumbnails",
        "better-wp-security", "wp-optimize", "redirection", "wp-smushit", "seo-by-rank-math",
        "litespeed-cache", "wp-rocket", "backupwordpress", "social-networks-auto-poster-facebook-twitter-g",
        "ml-slider", "tablepress", "wp-pagenavi", "contact-form-plugin", "tinymce-advanced"
    ]
    
    print(f"[*] Checking {len(common_plugins)} common plugins...")
    
    # Check plugins by accessing common files
    for plugin_slug in common_plugins:
        try:
            # Try to access the plugin's CSS file
            css_url = urljoin(base_url, f"wp-content/plugins/{plugin_slug}/{plugin_slug}.css")
            if css_url not in checked_urls:
                checked_urls.add(css_url)
                response = get_http_client().get(css_url, timeout=5)
                
                if response.status_code == 200:
                    # If CSS file is found, the plugin is likely installed
                    version = _extract_version_from_css(response.text)
                    detected_plugins.append({
                        "slug": plugin_slug,
                        "version": version or "unknown"
                    })
                    continue
                    
            # Try the JS file
            js_url = urljoin(base_url, f"wp-content/plugins/{plugin_slug}/{plugin_slug}.js")
            if js_url not in checked_urls:
                checked_urls.add(js_url)
                response = get_http_client().get(js_url, timeout=5)
                
                if response.status_code == 200:
                    version = _extract_version_from_js(response.text)
                    detected_plugins.append({
                        "slug": plugin_slug,
                        "version": version or "unknown"
                    })
                    continue
                    
            # Try the readme file
            readme_url = urljoin(base_url, f"wp-content/plugins/{plugin_slug}/readme.txt")
            if readme_url not in checked_urls:
                checked_urls.add(readme_url)
                response = get_http_client().get(readme_url, timeout=5)
                
                if response.status_code == 200:
                    version = _extract_version_from_readme(response.text)
                    detected_plugins.append({
                        "slug": plugin_slug,
                        "version": version or "unknown"
                    })
                    
        except Exception:
            # Skip if an error occurs
            continue
    
    # Method 2: Check via REST API (if enabled)
    try:
        rest_url = urljoin(base_url, "wp-json/wp/v2/plugins")
        response = get_http_client().get(rest_url, timeout=10)
        if response.status_code == 200:
            plugins_data = response.json()
            for plugin in plugins_data:
                # Extract plugin slug from plugin name (e.g., "contact-form-7/contact-form-7.php")
                plugin_name = plugin.get("plugin", "")
                if "/" in plugin_name:
                    slug = plugin_name.split("/")[0]
                    version = plugin.get("version", "unknown")
                    status = plugin.get("status", "inactive")
                    
                    # Only add active plugins
                    if status == "active":
                        # Check if plugin already exists in the list to avoid duplicates
                        if not any(p["slug"] == slug for p in detected_plugins):
                            detected_plugins.append({
                                "slug": slug,
                                "version": version,
                                "status": status
                            })
    except:  # noqa: E722
        # REST API may not be available or restricted
        pass
    
    # Method 3: Check from HTML page source for plugin signatures
    try:
        response = get_http_client().get(base_url, timeout=10)
        if response.status_code == 200:
            html_content = response.text
            # Search for plugin signatures in HTML
            additional_plugins = _extract_plugins_from_html(html_content)
            for plugin in additional_plugins:
                # Avoid duplicates
                if not any(p["slug"] == plugin["slug"] for p in detected_plugins):
                    detected_plugins.append(plugin)
    except:  # noqa: E722
        pass
    
    # Method 4: Check via generator meta tag or comment
    try:
        response = get_http_client().get(base_url, timeout=10)
        if response.status_code == 200:
            html_content = response.text
            # Check WordPress version from meta tag
            wp_version = _extract_wordpress_version(html_content)
            if wp_version:
                # Add as additional information
                pass
    except:  # noqa: E722
        pass
    
    return detected_plugins


def _extract_version_from_css(css_content: str) -> str:
    """
    Extract plugin version from CSS content.
    """
    version_patterns = [
        r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"v([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"version\s*=\s*['\"]([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)['\"]"
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, css_content, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return "unknown"


def _extract_version_from_js(js_content: str) -> str:
    """
    Extract plugin version from JavaScript content.
    """
    version_patterns = [
        r"version['\"]?\s*[:=]\s*['\"]([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)['\"]",
        r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"v([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)"
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, js_content, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return "unknown"


def _extract_version_from_readme(readme_content: str) -> str:
    """
    Extract plugin version from readme.txt file.
    """
    # Look for "Stable tag:" or "Version:" lines
    version_patterns = [
        r"Stable tag:\s*([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)"
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, readme_content, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return "unknown"


def _extract_plugins_from_html(html_content: str) -> List[Dict[str, str]]:
    """
    Extract plugins from HTML content based on signatures.
    """
    detected = []
    
    # Search for plugin signatures in script tags
    script_matches = re.findall(r'<script[^>]*src=[\'"][^\'"]*wp-content/plugins/([^/]+)/', html_content)
    for match in script_matches:
        if match not in [p["slug"] for p in detected]:
            detected.append({
                "slug": match,
                "version": "unknown"
            })
    
    # Search for plugin signatures in link tags (CSS)
    link_matches = re.findall(r'<link[^>]*href=[\'"][^\'"]*wp-content/plugins/([^/]+)/', html_content)
    for match in link_matches:
        if match not in [p["slug"] for p in detected]:
            detected.append({
                "slug": match,
                "version": "unknown"
            })
    
    return detected


def _extract_wordpress_version(html_content: str) -> str:
    """
    Extract WordPress version from HTML content.
    """
    # Search for generator meta tag
    match = re.search(r'<meta[^>]*name=[\'"]generator[\'"][^>]*content=[\'"][^\'"]*WordPress\s+([0-9]+\.[0-9]+\.[0-9]+)', html_content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Search in comment
    match = re.search(r'<!--[^>]*WordPress\s+([0-9]+\.[0-9]+\.[0-9]+)', html_content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return "unknown"


def scan_wordpress_site(base_url: str) -> Dict[str, Any]:
    """
    Perform comprehensive scanning of a WordPress site.
    
    Args:
        base_url: The base URL of the WordPress site
        
    Returns:
        Dictionary containing scan results
    """
    results = {
        "detected_plugins": [],
        "vulnerabilities": {},
        "scan_summary": {}
    }
    
    print("[*] Detecting installed WordPress plugins...")
    detected_plugins = detect_installed_plugins(base_url)
    results["detected_plugins"] = detected_plugins
    
    print(f"[+] Found {len(detected_plugins)} potential plugins")
    
    # Check vulnerabilities for each detected plugin
    vulnerable_plugins = 0
    total_vulns = 0
    
    for plugin in detected_plugins:
        slug = plugin["slug"]
        version = plugin["version"]
        
        print(f"[*] Checking vulnerabilities for {slug} (v{version})...")
        vuln_result = check_plugin_vulnerabilities(slug, version)
        
        if "vulnerabilities" in vuln_result:
            results["vulnerabilities"][slug] = vuln_result
            vulnerable_plugins += 1
            total_vulns += len(vuln_result.get("vulnerabilities", []))
        elif "error" in vuln_result:
            results["vulnerabilities"][slug] = vuln_result
        else:
            results["vulnerabilities"][slug] = {"note": "No vulnerabilities found"}
    
    results["scan_summary"] = {
        "total_plugins_detected": len(detected_plugins),
        "vulnerable_plugins": vulnerable_plugins,
        "total_vulnerabilities": total_vulns
    }
    
    return results
