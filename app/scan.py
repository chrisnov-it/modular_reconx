import argparse
import concurrent.futures
import logging
import re
import sys
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from pyfiglet import figlet_format
from termcolor import colored
import os

# Fix for relative imports when running as a script
if __name__ == "__main__" and __package__ is None:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(os.path.dirname(current_dir))
    sys.path.append(os.path.dirname(current_dir))
    sys.path.append(current_dir)
    __package__ = "app"

# Local application imports
from .modules.breach_check import check_email_breach
from .modules.builtwith_scan import detect_builtwith
from .modules.dns_lookup import get_dns
from .modules.geoip_lookup import geoip_lookup
from .modules.ip_lookup import get_ip
from .modules.path_bruteforce import bruteforce_paths
from .modules.port_scanner import scan_ports
from .modules.reverse_ip import reverse_ip_lookup
from .modules.social_finder import find_social_links
from .modules.ssl_cert_info import get_ssl_info
from .modules.subdomain_enum import enumerate_subdomains
from .modules.tech_stack import get_tech_stack
from .modules.reporting import save_report
from .modules.vuln_scanner import (
    check_versioned_vulnerabilities,
    search_general_vulnerabilities,
)
from .modules.wayback_machine import get_wayback_urls
from .modules.whois_lookup import get_whois
from .modules.wp_scanner import scan_wordpress_site
from .modules.ct_log_monitor import monitor_certificate_transparency

# Bug hunting modules
from .modules.param_analysis import comprehensive_param_analysis
from .modules.js_analysis import comprehensive_js_analysis
from .modules.api_discovery import comprehensive_api_discovery
from .modules.security_headers import comprehensive_security_analysis
from .modules.form_analysis import comprehensive_form_analysis
from .modules.cors_checker import comprehensive_cors_analysis
from .modules.cookie_analysis import comprehensive_cookie_analysis
from .modules.clickjacking_checker import comprehensive_clickjacking_analysis
from .modules.param_pollution import comprehensive_parameter_pollution_analysis

# New modules
from .modules.cloud_enum import check_cloud_storage
from .modules.metadata_analysis import analyze_metadata, analyze_local_file
from .modules.image_forensics import analyze_image, find_images
from .modules.social_eng import perform_social_recon
from .modules.reverse_image import generate_reverse_links, print_reverse_links
from .modules.ai_analysis import analyze_report_with_ai
from .modules.github_scanner import scan_github
from .modules.waf_detector import detect_waf
import os

# Load environment variables
load_dotenv()

# Version information
VERSION = "1.3.0"


def setup_logging() -> None:
    """
    Configures a file logger to record errors and important events.
    The log file is overwritten on each run.
    """
    # We configure the root logger to catch logs from all modules.
    # Using 'w' to overwrite the log file for each new scan session.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        filename="osint_tool.log",
        filemode="w",
    )


def validate_domain(domain: str) -> bool:
    """
    Validate domain name format.
    
    Args:
        domain: The domain name to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not domain or not isinstance(domain, str):
        return False
    
    # Remove whitespace
    domain = domain.strip()
    
    # Basic length check
    if len(domain) > 253:
        return False
    
    # Regex pattern for domain validation
    pattern = re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    
    return bool(pattern.match(domain))


def filter_related_domains(
    target_whois: Dict[str, Any], reverse_ip_results: Dict[str, Any]
) -> Dict[str, List[str]]:
    """
    Analyze reverse IP results and filter them based on WHOIS similarity.
    """
    filtered_results = {"likely_related": [], "other_neighbors": []}
    
    # Get registrar name from the main target domain
    target_registrar = target_whois.get("registrar")
    if not target_registrar or not reverse_ip_results.get("domains"):
        # If not enough data, return the list as is
        filtered_results["other_neighbors"] = reverse_ip_results.get("domains", [])
        return filtered_results
    
    # Get domain list from reverse IP results
    neighbor_domains = reverse_ip_results.get("domains", [])
    
    print(
        f"[*] Starting WHOIS correlation for {len(neighbor_domains)} neighboring domains (this may be slow)..."
    )
    
    for domain in neighbor_domains:
        # Validate domain before processing
        if not validate_domain(domain):
            filtered_results["other_neighbors"].append(domain)
            logging.warning(f"Invalid domain format for neighboring domain {domain}")
            continue
        
        # Call the whois module for each neighboring domain
        try:
            neighbor_whois = get_whois(domain)  # Calling get_whois function from module
            neighbor_registrar = neighbor_whois.get("registrar")
            
            # Compare registrars. This is a simple method, can be developed further
            if (
                neighbor_registrar
                and target_registrar.lower() == neighbor_registrar.lower()
            ):
                filtered_results["likely_related"].append(domain)
            else:
                filtered_results["other_neighbors"].append(domain)
        except Exception as e:
            # If WHOIS for neighboring domain fails, consider it unrelated
            filtered_results["other_neighbors"].append(domain)
            logging.warning(
                f"Failed to perform WHOIS lookup for neighboring domain {domain}: {e}"
            )
    
    return filtered_results


def scan(
    target: str,
    output_format: str = "json",
    skip_ports: bool = False,
    skip_bruteforce: bool = False,
    correlate_domains: bool = False,
    bug_hunt_mode: bool = False,
    cloud_enum: bool = False,
    metadata_analysis: bool = False,
    image_forensics: bool = False,
    social_eng: bool = False,
    reverse_image: bool = False,
    enhanced_subdomains: bool = False,
    ai_analyze: bool = False,
    github_scan: bool = False,
    waf_detection: bool = False,
) -> None:
    """
    Orchestrates the scanning process.
    
    Args:
        target: The domain name or local file path to scan.
        output_format: The format of the output report (json or txt).
        skip_ports: If True, skips the port scanning module.
        skip_bruteforce: If True, skips the path bruteforcing module.
        correlate_domains: If True, correlates reverse IP results with WHOIS data.
        bug_hunt_mode: If True, enables advanced bug hunting modules.
        cloud_enum: If True, enables cloud storage enumeration.
        metadata_analysis: If True, enables metadata analysis.
        image_forensics: If True, enables image forensics.
        social_eng: If True, enables social engineering recon.
        reverse_image: If True, enables reverse image search.
        enhanced_subdomains: If True, uses a larger wordlist for subdomains.
        ai_analyze: If True, uses AI to analyze the final report.
        github_scan: If True, scans GitHub for secrets.
        waf_detection: If True, detects Web Application Firewalls.
    """
    # Check if input is a local file
    if os.path.isfile(target):
        print(f"\n[FILE] Analyzing local file: {target}")
        logging.info(f"Starting analysis for local file: {target}")
        results: Dict[str, Any] = {"file": target}
        
        if target.lower().endswith(('.jpg', '.jpeg', '.png', '.heic', '.tiff')):
            print("[*] Detected image file. Running Image Forensics...")
            results["image_forensics"] = analyze_image(target, is_local=True)
            print("[+] Completed: Image Forensics")
            
            # For local files, we can't easily generate reverse links unless we upload it.
            # But if the user provided a URL (even if treating as 'file' input logic catches it?), 
            # actually os.path.isfile check prevents URLs here.
            # So we only support reverse search for URLs or scraped images.
            if reverse_image:
                print("[!] Reverse image search requires a public URL. Skipping for local file.")
            
            
        elif target.lower().endswith(('.pdf', '.docx')):
            print("[*] Detected document. Running Metadata Analysis...")
            results["metadata_analysis"] = analyze_local_file(target)
            print("[+] Completed: Metadata Analysis")
            
        else:
            print("[!] Unsupported file type for local analysis.")
            results["error"] = "Unsupported file type"
            
        filename = save_report(results, output_format)
        print(f"\n[+] Results saved to: {filename}\n")
        return

    domain = target
    # Validate input domain if not a file
    if not validate_domain(domain):
        print(f"[!] Invalid domain format: {domain}")
        logging.error(f"Invalid domain format: {domain}")
        return
    
    print(f"\n[SCAN] Starting OSINT scan for: {domain}")
    logging.info(f"Starting new OSINT scan for domain: {domain}")
    results: Dict[str, Any] = {"domain": domain}
    
    # Define scans that only need a domain name (passive)
    scans_to_run = {
        "whois": (get_whois, domain),
        "dns": (get_dns, domain),
        "subdomains": (lambda d: enumerate_subdomains(d, use_enhanced_wordlist=enhanced_subdomains), domain),
        "social_links": (find_social_links, domain),
        "wayback_urls": (get_wayback_urls, domain),
        "certificate_transparency": (monitor_certificate_transparency, domain),
    }
    
    # Initial IP lookup is blocking, as many other scans depend on it.
    print("[*] Looking up main IP...")
    ip = get_ip(domain)
    base_url = f"http://{domain}"
    
    # Determine if active scans that require a live host are possible.
    if not ip:
        print(f"  [!] Failed to get IP for {domain}. Active scans will be skipped.")
        logging.warning(f"Could not resolve IP for {domain}. Skipping active scans.")
        results["error"] = "IP address could not be resolved."
    else:
        results["ip_address"] = ip
        print(f"  [+] Found IP: {ip}")
        # base_url is already defined above
        
        # Add active scans to the list
        active_scans = {
            "tech_stack": (get_tech_stack, base_url),
            "builtwith": (detect_builtwith, domain),
            "geoip": (geoip_lookup, ip),
            "reverse_ip": (reverse_ip_lookup, ip),
            "ssl_certificate": (get_ssl_info, domain),
        }
        if not skip_ports:
            active_scans["open_ports"] = (scan_ports, ip)
        if not skip_bruteforce:
            active_scans["paths_found"] = (bruteforce_paths, base_url)
        scans_to_run.update(active_scans)
    
    # Use ThreadPoolExecutor for cleaner and more modern concurrency management.
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(scans_to_run)
    ) as executor:
        future_to_key = {
            executor.submit(func, *args): key
            for key, (func, *args) in scans_to_run.items()
        }
        
        print("[*] Running concurrent scans...")
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result()
                print(f"  [+] Completed: {key}")
            except Exception as exc:
                results[key] = {"error": f"Failed to run {key}: {exc}"}
                print(f"  [!] Failed: {key}")
                logging.error(
                    f"Module '{key}' failed for domain '{domain}'", exc_info=True
                )
    
    # --- IMPORTANT: Extract required results after all concurrent scans are complete ---
    builtwith_results = results.get("builtwith", {})
    tech_stack_results = results.get("tech_stack", {})
    
    # Get the primary email for breach checking from WHOIS results
    primary_email: Optional[str] = None
    whois_data = results.get("whois", {})
    if isinstance(whois_data, dict):
        whois_emails = whois_data.get("emails")
        if isinstance(whois_emails, list) and whois_emails:
            primary_email = whois_emails[0]
        elif isinstance(whois_emails, str):
            primary_email = whois_emails
    
    if primary_email:
        print("[*] Checking for data breaches for email...")
        results["breach_check"] = check_email_breach(primary_email)
        print("  [+] Completed: breach_check")
    else:
        results["breach_check"] = {"note": "No email found in WHOIS"}
    
    # Check for versioned vulnerabilities based on tech stack
    # Ensure builtwith_results is a dict and not an error or empty
    if builtwith_results and not builtwith_results.get("error"):
        print(
            "  [+] Starting: vulnerability check based on technology (Vulners.com)..."
        )
        results["vulnerabilities"] = check_versioned_vulnerabilities(
            builtwith_results, tech_stack_results
        )
        print("  [+] Completed: vulnerability check")
    else:  # This is the branch if builtwith_results is not available or there's an error
        results["vulnerabilities"] = {
            "note": "Version-specific vulnerability check skipped (BuiltWith data not available or error)."
        }
    
    # Perform general keyword vulnerability search
    print(
        "  [+] Starting: general vulnerability search based on keywords (Vulners.com)..."
    )
    # Use server or x_powered_by from tech_stack, or domain as fallback keyword
    keyword = (
        tech_stack_results.get("server")
        or tech_stack_results.get("x_powered_by")
        or domain
    )
    results["vulnerabilities_by_keyword"] = search_general_vulnerabilities(keyword)
    print("  [+] Completed: vulnerabilities_by_keyword")
    
    # --- "NOISY NEIGHBORS" CORRELATION FEATURE (FINAL VERSION) ---
    if correlate_domains:
        # This feature only runs if the user requests it with the --correlate flag
        print("\n[*] --correlate option active. Starting domain correlation...")
        if "error" not in results.get("reverse_ip", {}) and "error" not in results.get(
            "whois", {}
        ):
            correlated_domains = filter_related_domains(
                results["whois"], results["reverse_ip"]
            )
            results["correlated_reverse_ip"] = correlated_domains
            print("[+] Domain correlation completed.")
        else:
            results["correlated_reverse_ip"] = {
                "note": "Domain correlation skipped due to incomplete WHOIS or Reverse IP data."
            }
    else:
        # If no flag, don't add this key to the report
        pass
    
    # --- NEW FEATURE: WordPress Specific Scanner ---
    # Check for WordPress from various sources for better reliability
    is_wordpress = False
    generator_info = results.get("tech_stack", {}).get("generator", "")
    if generator_info and "wordpress" in generator_info.lower():
        is_wordpress = True
    
    # Fallback to check builtwith results if generator doesn't mention WordPress
    if not is_wordpress:
        builtwith_cms = results.get("builtwith", {}).get("cms", [])
        if any("wordpress" in cms.lower() for cms in builtwith_cms):
            is_wordpress = True
    
    if is_wordpress:
        print("\n[*] WordPress detected. Starting comprehensive plugin scan with WPScan...")
        
        # Use the enhanced WordPress scanner
        wpscan_results = scan_wordpress_site(base_url)
        
        # Save the results in the main report
        results["wpscan_results"] = wpscan_results
        print("[+] Completed: WPScan comprehensive scan")
        print(f"    - Plugins detected: {wpscan_results.get('scan_summary', {}).get('total_plugins_detected', 0)}")
        print(f"    - Vulnerable plugins: {wpscan_results.get('scan_summary', {}).get('vulnerable_plugins', 0)}")
        print(f"    - Total vulnerabilities: {wpscan_results.get('scan_summary', {}).get('total_vulnerabilities', 0)}")

    # --- NEW FEATURE: Bug Hunting Modules ---
    if bug_hunt_mode and ip:
        print("\n[*] Bug hunting mode enabled. Starting advanced security analysis...")
        
        # Parameter Analysis
        print("\n[*] Starting parameter analysis...")
        results["param_analysis"] = comprehensive_param_analysis(base_url)
        print("[+] Completed: parameter analysis")
        
        # JavaScript Analysis
        print("\n[*] Starting JavaScript analysis...")
        results["js_analysis"] = comprehensive_js_analysis(base_url)
        print("[+] Completed: JavaScript analysis")
        
        # API Discovery
        print("\n[*] Starting API endpoint discovery...")
        results["api_discovery"] = comprehensive_api_discovery(base_url)
        print("[+] Completed: API discovery")
        
        # Security Headers Analysis
        print("\n[*] Starting security headers analysis...")
        results["security_headers_analysis"] = comprehensive_security_analysis(base_url)
        print("[+] Completed: security headers analysis")
        
        # Form Analysis
        print("\n[*] Starting form analysis...")
        results["form_analysis"] = comprehensive_form_analysis(base_url)
        print("[+] Completed: form analysis")
        
        # CORS Analysis
        print("\n[*] Starting CORS misconfiguration analysis...")
        results["cors_analysis"] = comprehensive_cors_analysis(base_url)
        print("[+] Completed: CORS analysis")
        
        # Cookie Analysis
        print("\n[*] Starting cookie security analysis...")
        results["cookie_analysis"] = comprehensive_cookie_analysis(base_url)
        print("[+] Completed: cookie analysis")
        
        # Clickjacking Analysis
        print("\n[*] Starting clickjacking protection analysis...")
        results["clickjacking_analysis"] = comprehensive_clickjacking_analysis(base_url)
        print("[+] Completed: clickjacking analysis")
        
        # HTTP Parameter Pollution Analysis
        print("\n[*] Starting HTTP parameter pollution analysis...")
        results["param_pollution_analysis"] = comprehensive_parameter_pollution_analysis(base_url)
        print("[+] Completed: parameter pollution analysis")

    # --- NEW FEATURE: Cloud Enumeration ---
    if cloud_enum:
        print("\n[*] Starting cloud storage enumeration...")
        results["cloud_storage"] = check_cloud_storage(domain)
        print("[+] Completed: cloud storage enumeration")

    # --- NEW FEATURE: Metadata Analysis ---
    if metadata_analysis:
        print("\n[*] Starting metadata analysis (this may take a while)...")
        results["metadata_analysis"] = analyze_metadata(domain)
        results["metadata_analysis"] = analyze_metadata(domain)
        print("[+] Completed: metadata analysis")

    # --- NEW FEATURE: Image Forensics ---
    if image_forensics:
        print("\n[*] Starting image forensics...")
        # First find images
        print("  [*] Scraping domain for images...")
        images = find_images(domain)
        print(f"  [+] Found {len(images)} images.")
        
        results["image_forensics"] = {"images_found": images, "analysis": []}
        
        # Analyze top 5 images to avoid taking too long
        for img_url in images[:5]:
            print(f"  [*] Analyzing: {img_url}")
            analysis = analyze_image(img_url, is_local=False)
            results["image_forensics"]["analysis"].append(analysis)
            
            if reverse_image:
                print_reverse_links(img_url)
                # Add links to results
                analysis["reverse_links"] = generate_reverse_links(img_url)
            
        print("[+] Completed: image forensics")

    # --- NEW FEATURE: Social Engineering Recon ---
    if social_eng:
        print("\n[*] Starting social engineering reconnaissance...")
        # Pass found emails from WHOIS if available
        found_emails = []
        if primary_email:
            found_emails.append(primary_email)
            
        results["social_engineering"] = perform_social_recon(domain, found_emails)
        print("[+] Completed: social engineering recon")

    # --- NEW FEATURE: WAF Detection ---
    if waf_detection:
        print("\n[*] Detecting Web Application Firewall (WAF)...")
        results["waf_detection"] = detect_waf(domain)
        print(f"[+] Completed: WAF detection (Found: {results['waf_detection'].get('firewall', 'None')})")

    # --- NEW FEATURE: GitHub Scanning ---
    if github_scan:
        print("\n[*] Scanning GitHub for secrets and dorks...")
        results["github_scan"] = scan_github(domain)
        print("[+] Completed: GitHub scan")

    # --- NEW FEATURE: AI Analysis (Must be last) ---
    if ai_analyze:
        print("\n[*] Performing AI Analysis of the report (Gemini)...")
        ai_results = analyze_report_with_ai(results)
        results["ai_analysis"] = ai_results
        if "analysis" in ai_results:
            print("[+] AI Analysis completed successfully.")
            print("\n--- AI EXECUTIVE SUMMARY ---\n")
            print(colored(ai_results["analysis"], "yellow"))
            print("\n----------------------------\n")
        else:
            print(f"[!] AI Analysis failed or skipped: {ai_results.get('error') or ai_results.get('note')}")

    filename = save_report(results, output_format)
    print(f"\n[+] Results saved to: {filename}\n")


def main():
    """Main function to run the OSINT tool from the command line."""
    parser = argparse.ArgumentParser(
        description="Modular ReconX - Advanced OSINT reconnaissance tool."
    )
    parser.add_argument("target", help="The domain to scan (e.g., example.com) OR local file path")
    parser.add_argument(
        "--output",
        choices=["json", "txt", "csv", "html", "pdf"],
        default="json",
        help="The output format for the report (json, txt, csv, html, or pdf).",
    )
    parser.add_argument(
        "--skip-ports", action="store_true", help="Skip the port scanning module."
    )
    parser.add_argument(
        "--skip-bruteforce",
        action="store_true",
        help="Skip the path bruteforcing module.",
    )
    parser.add_argument(
        "--correlate",
        action="store_true",
        help="Correlate reverse IP results by checking WHOIS similarity (slow).",
    )
    parser.add_argument(
        "--bug-hunt",
        action="store_true",
        help="Enable comprehensive bug hunting mode with advanced security analysis.",
    )
    parser.add_argument(
        "--cloud",
        action="store_true",
        help="Enable cloud storage enumeration (AWS S3, Azure Blob, GCP Bucket).",
    )
    parser.add_argument(
        "--metadata",
        action="store_true",
        help="Enable metadata analysis of public documents (PDF, DOCX).",
    )
    parser.add_argument(
        "--forensics",
        action="store_true",
        help="Enable image forensics (EXIF data extraction).",
    )
    parser.add_argument(
        "--social",
        action="store_true",
        help="Enable social engineering reconnaissance (Dorks, Email Patterns).",
    )
    parser.add_argument(
        "--reverse",
        action="store_true",
        help="Enable reverse image search (Generates links for Google, Bing, etc.).",
    )
    parser.add_argument(
        "--enhanced-subdomains",
        action="store_true",
        help="Use a larger wordlist for subdomain enumeration (slower but more comprehensive).",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI analysis of the report using Google Gemini (requires GEMINI_API_KEY).",
    )
    parser.add_argument(
        "--github",
        action="store_true",
        help="Enable GitHub secret scanning (uses GITHUB_TOKEN if available, else dorks).",
    )
    parser.add_argument(
        "--waf",
        action="store_true",
        help="Enable Web Application Firewall (WAF) detection.",
    )
    parser.add_argument(
        "--version", action="version", version=f"Modular ReconX v{VERSION}"
    )
    setup_logging()
    args = parser.parse_args()
    
    # Validate input domain
    target = args.target.strip()
    
    # If it's a file, we skip domain validation
    if not os.path.isfile(target):
        if not validate_domain(target):
            print(f"[!] Invalid domain format or file not found: {target}")
            sys.exit(1)
    
    banner = figlet_format("Modular ReconX", font="slant")
    print(colored(banner, "cyan"))
    print(
        colored(
            f"Advanced OSINT Tool v{VERSION} | Made with <3 by Chrisnov & Nai Momang | Cybersecurity Researchers\n",
            "magenta",
        )
    )
    
    scan(
        target,
        output_format=args.output,
        skip_ports=args.skip_ports,
        skip_bruteforce=args.skip_bruteforce,
        correlate_domains=args.correlate,
        bug_hunt_mode=args.bug_hunt,
        cloud_enum=args.cloud,
        metadata_analysis=args.metadata,
        image_forensics=args.forensics,
        social_eng=args.social,
        reverse_image=args.reverse,
        enhanced_subdomains=args.enhanced_subdomains,
        ai_analyze=args.ai,
        github_scan=args.github,
        waf_detection=args.waf,
    )


if __name__ == "__main__":
    main()