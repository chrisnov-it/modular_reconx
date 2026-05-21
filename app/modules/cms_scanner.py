
import re
import logging
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .http_client import get_http_client

# Setup logger
logger = logging.getLogger(__name__)

# --- CMS Specific Signatures and Checks ---

def scan_drupal(base_url: str) -> Dict[str, Any]:
    """Deep scan for Drupal."""
    results = {"detected": True, "cms": "Drupal", "version": "unknown", "exposure": []}
    
    # 1. Version Detection via CHANGELOG.txt (common in older Drupal)
    cl_url = urljoin(base_url, "CHANGELOG.txt")
    try:
        r = get_http_client().get(cl_url, timeout=5)
        if r.status_code == 200 and "Drupal" in r.text:
            # Extract version
            match = re.search(r"Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", r.text)
            if match:
                results["version"] = match.group(1)
                results["exposure"].append("CHANGELOG.txt is publicly accessible (Information Disclosure)")
    except Exception:
        pass

    # 2. Check for sensitive paths
    paths = [
        ("install.php", "Installation script exposed"),
        ("update.php", "Update script exposed"),
        ("sites/default/settings.php", "Settings file exposed (Critical if readable)"),
        ("sites/default/files/", "Files directory listing enabled"),
        ("user/register", "User registration page exposed"),
        ("node/add", "Content creation page exposed"),
    ]
    
    for path, desc in paths:
        try:
            full_url = urljoin(base_url, path)
            r = get_http_client().get(full_url, timeout=5)
            if r.status_code == 200:
                # Filter out soft 200s (custom error pages that return 200)
                if "page not found" not in r.text.lower() and "access denied" not in r.text.lower():
                     results["exposure"].append(f"Exposed: {path} ({desc})")
        except Exception:
            pass

    # 3. Header check for version (X-Generator)
    try:
        r = get_http_client().get(base_url, timeout=5)
        gen = r.headers.get("X-Generator", "")
        if "Drupal" in gen and results["version"] == "unknown":
            match = re.search(r"Drupal\s+([0-9]+)", gen)
            if match:
                results["version"] = match.group(1) + ".x"
    except:
        pass

    return results

def scan_joomla(base_url: str) -> Dict[str, Any]:
    """Deep scan for Joomla."""
    results = {"detected": True, "cms": "Joomla", "version": "unknown", "exposure": []}
    
    # 1. Check for XML manifest files (Joomla specific)
    manifests = [
        "administrator/manifests/files/joomla.xml",
        "language/en-GB/en-GB.xml",
        "administrator/language/en-GB/en-GB.xml"
    ]
    
    for manifest in manifests:
        try:
            url = urljoin(base_url, manifest)
            r = get_http_client().get(url, timeout=5)
            if r.status_code == 200 and "xml" in r.headers.get("Content-Type", ""):
                 match = re.search(r"<version>([^<]+)</version>", r.text)
                 if match:
                     results["version"] = match.group(1)
                     results["exposure"].append(f"Manifest file exposed: {manifest} (Version Disclosure)")
                     break
        except:
            pass
            
    # 2. Check for sensitive paths
    paths = [
        ("administrator/", "Admin login panel exposed"),
        ("configuration.php", "Configuration file (Critical if readable, usually denied)"),
        ("htaccess.txt", "Example htaccess file exposed"),
        ("web.config.txt", "Example web.config file exposed"),
        ("images/", "Images directory listing"),
    ]
    
    for path, desc in paths:
        try:
            full_url = urljoin(base_url, path)
            r = get_http_client().get(full_url, timeout=5)
            if r.status_code == 200 and "login" in r.text.lower():
                 results["exposure"].append(f"Exposed: {path} ({desc})")
            elif r.status_code == 200 and "directory listing" in r.text.lower():
                 results["exposure"].append(f"Directory Listing: {path}")
            elif r.status_code == 200 and path.endswith(".txt"):
                 results["exposure"].append(f"Exposed: {path} ({desc})")
    
        except:
            pass

    return results

def scan_magento(base_url: str) -> Dict[str, Any]:
    """Deep scan for Magento (Adobe Commerce)."""
    results = {"detected": True, "cms": "Magento", "version": "unknown", "exposure": []}
    
    # 1. Version Check via RELEASE_NOTES.txt or LICENSE.txt (older)
    files = ["RELEASE_NOTES.txt", "LICENSE.txt", "js/mage/cookies.js"]
    for f in files:
         try:
            url = urljoin(base_url, f)
            r = get_http_client().get(url, timeout=5)
            if r.status_code == 200:
                if "Magento" in r.text:
                    results["exposure"].append(f"Exposed file: {f}")
         except:
             pass
    
    # 2. Admin Path Enumeration
    # Magento admins are often custom, but we can try common ones
    admin_paths = ["admin", "administrator", "backend", "magento_admin", "user"]
    for path in admin_paths:
        try:
            url = urljoin(base_url, path)
            r = get_http_client().get(url, timeout=5)
            # Magento admin usually redirects to a login page with a specific key
            if r.status_code == 200 and ("magento" in r.text.lower() or "login" in r.text.lower()):
                 results["exposure"].append(f"Possible Admin Path: /{path}")
                 break
        except:
            pass
            
    # 3. Check for specific Magento 2 API endpoint visibility
    try:
        api_url = urljoin(base_url, "rest/V1/store/storeConfigs")
        r = get_http_client().get(api_url, timeout=5)
        if r.status_code == 200:
            results["exposure"].append("REST API Accessible (may leak configuration info)")
    except:
        pass

    return results

def scan_moodle(base_url: str) -> Dict[str, Any]:
    """Deep scan for Moodle (LMS)."""
    results = {"detected": True, "cms": "Moodle", "version": "unknown", "exposure": []}
    
    # 1. Version Detection from releases note or npm-shrinkwrap (sometimes exposed)
    urls = [
        ("lib/upgrade.txt", r"([0-9]+\.[0-9]+\.[0-9]+)"),
        ("composer.json", r"\"version\":\s*\"([^\"]+)\"")
    ]
    
    for path, regex in urls:
        try:
             url = urljoin(base_url, path)
             r = get_http_client().get(url, timeout=5)
             if r.status_code == 200:
                 match = re.search(regex, r.text)
                 if match:
                     results["version"] = match.group(1)
                     results["exposure"].append(f"Exposed {path} (Version Disclosure)")
        except:
            pass
            
    # 2. Check for open registration
    try:
        reg_url = urljoin(base_url, "login/signup.php")
        r = get_http_client().get(reg_url, timeout=5)
        if r.status_code == 200 and "New account" in r.text:
            results["exposure"].append("Open User Registration found at /login/signup.php")
    except:
        pass
        
    # 3. Check for exposed sensitive files
    files = ["config.php", "install.php", "README.txt", "COPYING.txt"]
    for f in files:
        try:
            url = urljoin(base_url, f)
            r = get_http_client().get(url, timeout=5)
            if r.status_code == 200:
                results["exposure"].append(f"Exposed file: {f}")
        except:
            pass

    return results

def detect_cms(base_url: str) -> Optional[str]:
    """
    Attempt to fingerprint the CMS to decide which deep scan to run.
    This is a quick heuristic check using requests/headers/meta.
    """
    try:
        response = get_http_client().get(base_url, timeout=10, allow_redirects=True)
        html_content = response.text.lower()
        headers = response.headers
        
        # 1. Header Checks
        generator = headers.get("X-Generator", "").lower()
        if "drupal" in generator: return "drupal"
        if "joomla" in generator: return "joomla"
        
        # 2. Meta Tag Checks
        soup = BeautifulSoup(html_content, 'html.parser')
        meta_gen = soup.find("meta", attrs={"name": "generator"})
        if meta_gen:
            content = meta_gen.get("content", "").lower()
            if "drupal" in content: return "drupal"
            if "joomla" in content: return "joomla"
            if "magento" in content or "adobe commerce" in content: return "magento"
            if "moodle" in content: return "moodle"
            if "wordpress" in content: return "wordpress" # We have a separate scanner for this

        # 3. HTML Structure/Script Checks
        if "wp-content" in html_content: return "wordpress"
        if "sites/default/files" in html_content: return "drupal"
        if "/templates/system/css/system.css" in html_content or "joomla!" in html_content: return "joomla"
        if "mage/cookies.js" in html_content or "skin/frontend" in html_content: return "magento"
        if "theme/yui_combo.php" in html_content or "moodle" in html_content: return "moodle"
        
    except Exception as e:
        logger.error(f"Error during CMS detection: {e}")
        
    return None

def comprehensive_cms_fingerprint(base_url: str) -> Dict[str, Any]:
    """
    Main entry point for CMS fingerprinting module.
    Detects CMS and runs specific deep scans.
    """
    print(f"[*] Attempting to fingerprint CMS for: {base_url}")
    
    cms = detect_cms(base_url)
    results = {"detected_cms": cms, "scan_details": {}}
    
    if not cms:
        print("[-] No common CMS (Drupal, Joomla, Magento, Moodle, WP) detected via simple fingerprints.")
        return results

    print(f"[+] Detected CMS: {cms.upper()}")
    
    if cms == "drupal":
        print("[*] Running Deep Drupal Scan...")
        results["scan_details"] = scan_drupal(base_url)
    elif cms == "joomla":
        print("[*] Running Deep Joomla Scan...")
        results["scan_details"] = scan_joomla(base_url)
    elif cms == "magento":
        print("[*] Running Deep Magento Scan...")
        results["scan_details"] = scan_magento(base_url)
    elif cms == "moodle":
        print("[*] Running Deep Moodle Scan...")
        results["scan_details"] = scan_moodle(base_url)
    elif cms == "wordpress":
        print("[!] Target is WordPress. Using specialized WP module instead.")
        results["note"] = "Target is WordPress. Use standard scan logic which covers WP automatically."
    
    print(f"[+] CMS Fingerprinting Complete.")
    return results
