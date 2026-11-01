"""
Modular ReconX - Main scanner entrypoint (REFACTORED).

This is a refactored version that splits the monolithic scan() function into
smaller, focused helper functions. Behavior is identical to the original.
"""
import argparse
import concurrent.futures
import logging
import re
import sys
from typing import Any, Dict, List, Literal, Optional

from dotenv import load_dotenv
from pyfiglet import figlet_format
from termcolor import colored
import os

# Fix for relative imports when running as a script
if __name__ == "__main__" and __package__ is None:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(os.path.dirname(current_dir))
    sys.path.insert(0, os.path.dirname(current_dir))
    __package__ = "app"

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
from .modules.http_client import configure_http_client, get_http_client
from .modules.param_analysis import comprehensive_param_analysis
from .modules.js_analysis import comprehensive_js_analysis
from .modules.api_discovery import comprehensive_api_discovery
from .modules.security_headers import comprehensive_security_analysis
from .modules.form_analysis import comprehensive_form_analysis
from .modules.cors_checker import comprehensive_cors_analysis
from .modules.cookie_analysis import comprehensive_cookie_analysis
from .modules.clickjacking_checker import comprehensive_clickjacking_analysis
from .modules.param_pollution import comprehensive_parameter_pollution_analysis
from .modules.xss_scanner import scan_xss
from .modules.cloud_enum import check_cloud_storage
from .modules.metadata_analysis import analyze_metadata, analyze_local_file
from .modules.image_forensics import analyze_image, find_images
from .modules.social_eng import perform_social_recon
from .modules.reverse_image import generate_reverse_links, print_reverse_links
from .modules.ai_analysis import analyze_report_with_ai
from .modules.github_scanner import scan_github
from .modules.waf_detector import detect_waf
from .modules.cms_scanner import comprehensive_cms_fingerprint
from .modules.scoring import VulnerabilityScorer
from .modules.advanced_vuln_detection import run_advanced_vulnerability_detection

# Alias untuk tipe profile (disalin dari file asli)
ScanProfile = Literal["passive", "safe", "active", "aggressive"]


# ---------------------------------------------------------------------------
# Helper: setup & validation
# ---------------------------------------------------------------------------

def setup_logging() -> None:
    """Configure logging (sama seperti asli)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def validate_domain(domain: str) -> bool:
    """Validasi format domain sederhana."""
    if not domain:
        return False
    if len(domain) > 253:
        return False
    # pola domain dasar
    pattern = re.compile(
        r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}(?!-)$"
    )
    return bool(pattern.match(domain))


def resolve_base_url(domain: str) -> str:
    """Coba HTTPS dulu, fallback ke HTTP."""
    import urllib.request

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as r:
                return url
        except Exception:
            continue
    return f"https://{domain}"


def normalize_scan_profile(profile: ScanProfile, passive_only: bool) -> ScanProfile:
    """Normalisasi profile sesuai mode passive_only."""
    if passive_only:
        return "passive"
    return profile if profile in ("passive", "safe", "active", "aggressive") else "active"


def filter_related_domains(whois_data: dict, reverse_ip_data: dict) -> list:
    """Correlate WHOIS + reverse IP (logika ringkas dari asli)."""
    related = []
    org = whois_data.get("org") or whois_data.get("registrant_org")
    if org:
        related.append({"type": "whois_org", "value": org})
    ips = reverse_ip_data.get("related_ips", []) if isinstance(reverse_ip_data, dict) else []
    for item in ips[:10]:
        if isinstance(item, dict) and item.get("domain"):
            related.append({"type": "reverse_ip", "value": item["domain"]})
    return related


# ---------------------------------------------------------------------------
# Helper: fase-fase scan
# ---------------------------------------------------------------------------

def _scan_local_file(target: str, output_format: str, reverse_image: bool):
    """Fase 1: analisis file lokal."""
    print(f"\n[FILE] Analyzing local file: {target}")
    logging.info(f"Starting analysis for local file: {target}")
    results: Dict[str, Any] = {"file": target}

    if target.lower().endswith((".jpg", ".jpeg", ".png", ".heic", ".tiff")):
        print("[*] Detected image file. Running Image Forensics...")
        results["image_forensics"] = analyze_image(target, is_local=True)
        print("[+] Completed: Image Forensics")
        if reverse_image:
            print("[!] Reverse image search requires a public URL. Skipping for local file.")

    elif target.lower().endswith((".pdf", ".docx")):
        print("[*] Detected document. Running Metadata Analysis...")
        results["metadata_analysis"] = analyze_local_file(target)
        print("[+] Completed: Metadata Analysis")
    else:
        print("[!] Unsupported file type for local analysis.")
        results["error"] = "Unsupported file type"

    filename = save_report(results, output_format)
    print(f"\n[+] Results saved to: {filename}\n")
    return results, filename


def _build_scan_tasks(
    domain: str,
    ip: Optional[str],
    enhanced_subdomains: bool,
    allow_active: bool,
    passive_only: bool,
    skip_ports: bool,
    skip_bruteforce: bool,
    effective_profile: str,
) -> dict:
    """Fase 2: bangun kamus tasks yang akan dijalankan paralel."""
    scans_to_run = {
        "whois": (get_whois, domain),
        "dns": (get_dns, domain),
        "subdomains": (
            lambda d: enumerate_subdomains(d, use_enhanced_wordlist=enhanced_subdomains),
            domain,
        ),
        "social_links": (find_social_links, domain),
        "wayback_urls": (get_wayback_urls, domain),
        "certificate_transparency": (monitor_certificate_transparency, domain),
    }

    if ip and not passive_only:
        base_url = resolve_base_url(domain)
        active_scans = {
            "tech_stack": (get_tech_stack, base_url),
            "builtwith": (detect_builtwith, domain),
            "geoip": (geoip_lookup, ip),
            "reverse_ip": (reverse_ip_lookup, ip),
            "ssl_certificate": (get_ssl_info, domain),
        }
        if allow_active and not skip_ports:
            active_scans["open_ports"] = (scan_ports, ip)
        else:
            active_scans["open_ports"] = {"note": f"Skipped in {effective_profile} profile."}
        if allow_active and not skip_bruteforce:
            active_scans["paths_found"] = (bruteforce_paths, base_url)
        else:
            active_scans["paths_found"] = {"note": f"Skipped in {effective_profile} profile."}
        scans_to_run.update(active_scans)

    return scans_to_run


def _run_concurrent_scans(scans_to_run: dict, results: dict):
    """Fase 3: eksekusi paralel dengan ThreadPoolExecutor."""
    print("[*] Running concurrent scans...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(scans_to_run)) as executor:
        future_to_key = {
            executor.submit(func, *args): key
            for key, (func, *args) in scans_to_run.items()
        }
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result()
                print(f"  [+] Completed: {key}")
            except Exception as exc:
                results[key] = {"error": f"Failed to run {key}: {exc}"}
                print(f"  [!] Failed: {key}")
                logging.error(f"Module '{key}' failed for domain", exc_info=True)


def _postprocess_core(results: dict, domain: str, allow_active: bool, passive_only: bool, correlate_domains: bool):
    """Fase 4: breach check, vuln by keyword, correlate domains."""
    builtwith_results = results.get("builtwith", {})
    tech_stack_results = results.get("tech_stack", {})

    # Breach check dari email WHOIS
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

    # Versioned vulnerabilities
    if builtwith_results and not builtwith_results.get("error"):
        print("  [+] Starting: vulnerability check based on technology (Vulners.com)...")
        results["vulnerabilities"] = check_versioned_vulnerabilities(builtwith_results, tech_stack_results)
        print("  [+] Completed: vulnerability check")
    else:
        results["vulnerabilities"] = {
            "note": "Version-specific vulnerability check skipped (BuiltWith data not available or error)."
        }

    # General keyword vulnerability search
    if not passive_only:
        print("  [+] Starting: general vulnerability search based on keywords (Vulners.com)...")
        keyword = tech_stack_results.get("server") or tech_stack_results.get("x_powered_by") or domain
        results["vulnerabilities_by_keyword"] = search_general_vulnerabilities(keyword)
        print("  [+] Completed: vulnerabilities_by_keyword")
    else:
        results["vulnerabilities_by_keyword"] = {
            "note": "Skipped in passive-only mode because no active technology fingerprint was collected."
        }

    # Correlate domains
    if correlate_domains:
        print("\n[*] --correlate option active. Starting domain correlation...")
        if "error" not in results.get("reverse_ip", {}) and "error" not in results.get("whois", {}):
            results["correlated_reverse_ip"] = filter_related_domains(
                results["whois"], results["reverse_ip"]
            )
            print("[+] Domain correlation completed.")
        else:
            results["correlated_reverse_ip"] = {
                "note": "Domain correlation skipped due to incomplete WHOIS or Reverse IP data."
            }

    return results


def _postprocess_wordpress(results: dict, base_url: str, allow_active: bool, effective_profile: str):
    """Fase 5: deteksi WordPress + WPScan."""
    is_wordpress = False
    generator_info = results.get("tech_stack", {}).get("generator", "")
    if generator_info and "wordpress" in generator_info.lower():
        is_wordpress = True
    if not is_wordpress:
        builtwith_cms = results.get("builtwith", {}).get("cms", [])
        if any("wordpress" in cms.lower() for cms in builtwith_cms):
            is_wordpress = True

    if is_wordpress and allow_active:
        print("\n[*] WordPress detected. Starting comprehensive plugin scan with WPScan...")
        wpscan_results = scan_wordpress_site(base_url)
        results["wpscan_results"] = wpscan_results
        print("[+] Completed: WPScan comprehensive scan")
    elif is_wordpress:
        results["wpscan_results"] = {"note": f"Skipped in {effective_profile} profile."}
    return results


def _postprocess_bug_hunt(results: dict, base_url: str, bug_hunt_mode: bool, passive_only: bool, allow_aggressive: bool, ip: Optional[str]):
    """Fase 6: semua modul bug hunting."""
    if bug_hunt_mode and passive_only:
        print("\n[!] Bug hunting mode requested but skipped because --passive-only is active.")
        results["bug_hunt"] = {"note": "Skipped because passive-only mode is active."}
    elif bug_hunt_mode and not allow_aggressive:
        results["bug_hunt"] = {"note": "Skipped because --bug-hunt requires --profile aggressive."}
    elif bug_hunt_mode and ip:
        print("\n[*] Bug hunting mode enabled. Starting advanced security analysis...")

        print("\n[*] Starting parameter analysis...")
        results["param_analysis"] = comprehensive_param_analysis(base_url)
        print("[+] Completed: parameter analysis")

        print("\n[*] Starting JavaScript analysis...")
        results["js_analysis"] = comprehensive_js_analysis(base_url)
        print("[+] Completed: JavaScript analysis")

        print("\n[*] Starting API endpoint discovery...")
        results["api_discovery"] = comprehensive_api_discovery(base_url)
        print("[+] Completed: API discovery")

        print("\n[*] Starting security headers analysis...")
        results["security_headers_analysis"] = comprehensive_security_analysis(base_url)
        print("[+] Completed: security headers analysis")

        print("\n[*] Starting form analysis...")
        results["form_analysis"] = comprehensive_form_analysis(base_url)
        print("[+] Completed: form analysis")

        print("\n[*] Starting CORS misconfiguration analysis...")
        results["cors_analysis"] = comprehensive_cors_analysis(base_url)
        print("[+] Completed: CORS analysis")

        print("\n[*] Starting cookie security analysis...")
        results["cookie_analysis"] = comprehensive_cookie_analysis(base_url)
        print("[+] Completed: cookie analysis")

        print("\n[*] Starting clickjacking protection analysis...")
        results["clickjacking_analysis"] = comprehensive_clickjacking_analysis(base_url)
        print("[+] Completed: clickjacking analysis")

        print("\n[*] Starting HTTP parameter pollution analysis...")
        results["param_pollution_analysis"] = comprehensive_parameter_pollution_analysis(base_url)
        print("[+] Completed: parameter pollution analysis")

        print("\n[*] Starting Reflected XSS Fuzzing...")
        results["xss_scan"] = scan_xss(base_url)
        print("[+] Completed: XSS fuzzing")

        print("\n[*] Running advanced vulnerability detection...")
        advanced_results = run_advanced_vulnerability_detection(base_url)
        results["advanced_vuln_detection"] = advanced_results
        print("[+] Completed: Advanced vulnerability detection")

        print("\n[*] Analyzing security findings and generating risk assessment...")
        scorer = VulnerabilityScorer()
        scoring_results = scorer.analyze_bug_hunt_results(results)
        results["security_assessment"] = scoring_results
        print("[+] Completed: Security assessment")
        print(f"    - Overall Risk Score: {scoring_results['overall_score']:.1f}/100 ({scoring_results['risk_level']})")
        print(f"    - Total Findings: {len(scoring_results['findings'])}")

    return results


def _postprocess_optional(results: dict, domain: str, base_url: str, opts: dict):
    """Fase 7: fitur opsional (cloud, metadata, image, social, cms, waf, github, ai)."""
    if opts.get("cloud_enum"):
        print("\n[*] Starting cloud storage enumeration...")
        results["cloud_storage"] = check_cloud_storage(domain)
        print("[+] Completed: cloud storage enumeration")

    if opts.get("metadata_analysis"):
        print("\n[*] Starting metadata analysis...")
        results["metadata_analysis"] = analyze_metadata(domain)
        print("[+] Completed: metadata analysis")

    if opts.get("image_forensics") and not opts.get("allow_safe_active"):
        print(f"\n[!] Image forensics skipped in {opts['effective_profile']} profile.")
        results["image_forensics"] = {"note": f"Skipped in {opts['effective_profile']} profile."}
    elif opts.get("image_forensics"):
        print("\n[*] Starting image forensics...")
        print("  [*] Scraping domain for images...")
        images = find_images(base_url)
        print(f"  [+] Found {len(images)} images.")
        results["image_forensics"] = {"images_found": images, "analysis": []}
        for img_url in images:
            print(f"  [*] Analyzing: {img_url}")
            analysis = analyze_image(img_url, is_local=False)
            results["image_forensics"]["analysis"].append(analysis)
            if opts.get("reverse_image"):
                links = generate_reverse_links(img_url)
                print_reverse_links(links)
        print("[+] Completed: image forensics")

    if opts.get("social_eng"):
        print("\n[*] Starting social engineering reconnaissance...")
        primary_email = None
        whois_data = results.get("whois", {})
        if isinstance(whois_data, dict):
            emails = whois_data.get("emails")
            if isinstance(emails, list) and emails:
                primary_email = emails[0]
            elif isinstance(emails, str):
                primary_email = emails
        found_emails = [primary_email] if primary_email else []
        results["social_engineering"] = perform_social_recon(domain, found_emails)
        print("[+] Completed: social engineering recon")

    if opts.get("deep_cms_analysis") and not opts.get("allow_safe_active"):
        print(f"\n[!] Deep CMS fingerprinting skipped in {opts['effective_profile']} profile.")
        results["cms_fingerprint"] = {"note": f"Skipped in {opts['effective_profile']} profile."}
    elif opts.get("deep_cms_analysis"):
        print("\n[*] Starting Deep CMS Fingerprinting (Drupal/Joomla/Magento/Moodle)...")
        results["cms_fingerprint"] = comprehensive_cms_fingerprint(base_url)
        print("[+] Completed: CMS fingerprinting")

    if opts.get("waf_detection") and not opts.get("allow_active"):
        print(f"\n[!] WAF detection skipped in {opts['effective_profile']} profile.")
        results["waf_detection"] = {"note": f"Skipped in {opts['effective_profile']} profile."}
    elif opts.get("waf_detection"):
        print("\n[*] Detecting Web Application Firewall (WAF)...")
        results["waf_detection"] = detect_waf(domain)
        print(f"[+] Completed: WAF detection (Found: {results['waf_detection'].get('firewall', 'None')})")

    if opts.get("github_scan"):
        print("\n[*] Scanning GitHub for secrets and dorks...")
        results["github_scan"] = scan_github(domain)
        print("[+] Completed: GitHub scan")

    if opts.get("ai_analyze"):
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

    return results


# ---------------------------------------------------------------------------
# Fungsi utama scan() — sekarang pendek & jelas
# ---------------------------------------------------------------------------

def scan(
    target: str,
    output_format: str = "json",
    skip_ports: bool = False,
    skip_bruteforce: bool = False,
    passive_only: bool = False,
    profile: ScanProfile = "active",
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
    deep_cms_analysis: bool = False,
) -> Optional[tuple[Dict[str, Any], str]]:
    """
    Orchestrates the scanning process (refactored into phases).
    """
    # --- Fase 0: local file ---
    if os.path.isfile(target):
        return _scan_local_file(target, output_format, reverse_image)

    # --- Fase 0.5: setup domain ---
    domain = target
    effective_profile = normalize_scan_profile(profile, passive_only)
    passive_only = effective_profile == "passive"
    allow_safe_active = effective_profile in ("safe", "active", "aggressive")
    allow_active = effective_profile in ("active", "aggressive")
    allow_aggressive = effective_profile == "aggressive"

    if not validate_domain(domain):
        print(f"[!] Invalid domain format: {domain}")
        logging.error(f"Invalid domain format: {domain}")
        return None

    print(f"\n[SCAN] Starting OSINT scan for: {domain}")
    print(f"[*] Scan profile: {effective_profile}")
    if passive_only:
        print("[*] Passive-only mode enabled. Active scans and target probing will be skipped.")
    elif bug_hunt_mode and not allow_aggressive:
        print("[!] Bug hunting mode requested but requires --profile aggressive. It will be skipped.")
    logging.info(f"Starting new OSINT scan for domain: {domain}")

    results: Dict[str, Any] = {"domain": domain, "scan_profile": effective_profile}

    # --- Fase 1: IP lookup (blocking, dependensi banyak scan) ---
    print("[*] Looking up main IP...")
    ip = get_ip(domain)
    base_url = f"https://{domain}"

    if not ip:
        print(f"  [!] Failed to get IP for {domain}. Active scans will be skipped.")
        logging.warning(f"Could not resolve IP for {domain}. Skipping active scans.")
        results["error"] = "IP address could not be resolved."
    elif passive_only:
        results["ip_address"] = ip
        print(f"  [+] Found IP: {ip}")
        logging.info("Passive-only mode active. Skipping active scans for %s.", domain)
    else:
        results["ip_address"] = ip
        print(f"  [+] Found IP: {ip}")
        print("[*] Resolving HTTP base URL (HTTPS first)...")
        base_url = resolve_base_url(domain)
        results["base_url"] = base_url
        print(f"  [+] Using base URL: {base_url}")

    # --- Fase 2: bangun tasks ---
    scans_to_run = _build_scan_tasks(
        domain, ip, enhanced_subdomains, allow_active, passive_only,
        skip_ports, skip_bruteforce, effective_profile,
    )

    # --- Fase 3: eksekusi paralel ---
    if scans_to_run:
        _run_concurrent_scans(scans_to_run, results)

    # --- Fase 4: post-processing inti ---
    _postprocess_core(results, domain, allow_active, passive_only, correlate_domains)

    # --- Fase 5: WordPress ---
    _postprocess_wordpress(results, base_url, allow_active, effective_profile)

    # --- Fase 6: bug hunt ---
    _postprocess_bug_hunt(results, base_url, bug_hunt_mode, passive_only, allow_aggressive, ip)

    # --- Fase 7: opsional ---
    opts = {
        "cloud_enum": cloud_enum,
        "metadata_analysis": metadata_analysis,
        "image_forensics": image_forensics,
        "reverse_image": reverse_image,
        "social_eng": social_eng,
        "deep_cms_analysis": deep_cms_analysis,
        "waf_detection": waf_detection,
        "github_scan": github_scan,
        "ai_analyze": ai_analyze,
        "allow_active": allow_active,
        "allow_safe_active": allow_safe_active,
        "effective_profile": effective_profile,
    }
    _postprocess_optional(results, domain, base_url, opts)

    # --- Fase 8: simpan laporan ---
    filename = save_report(results, output_format)
    print(f"\n[+] Results saved to: {filename}\n")
    return results, filename


def main():
    """Main function to run the OSINT tool from the command line."""
    parser = argparse.ArgumentParser(
        description="Modular ReconX - Advanced OSINT reconnaissance tool."
    )
    parser.add_argument("target", help="Domain or file to scan")
    parser.add_argument("--output-format", choices=["json", "txt"], default="json")
    parser.add_argument("--skip-ports", action="store_true")
    parser.add_argument("--skip-bruteforce", action="store_true")
    parser.add_argument("--passive-only", action="store_true")
    parser.add_argument("--profile", choices=["passive", "safe", "active", "aggressive"], default="active")
    parser.add_argument("--correlate-domains", action="store_true")
    parser.add_argument("--bug-hunt", action="store_true")
    parser.add_argument("--cloud-enum", action="store_true")
    parser.add_argument("--metadata-analysis", action="store_true")
    parser.add_argument("--image-forensics", action="store_true")
    parser.add_argument("--social-eng", action="store_true")
    parser.add_argument("--reverse-image", action="store_true")
    parser.add_argument("--enhanced-subdomains", action="store_true")
    parser.add_argument("--ai-analyze", action="store_true")
    parser.add_argument("--github-scan", action="store_true")
    parser.add_argument("--waf-detection", action="store_true")
    parser.add_argument("--deep-cms-analysis", action="store_true")

    args = parser.parse_args()
    setup_logging()
    configure_http_client()
    scan(
        args.target,
        output_format=args.output_format,
        skip_ports=args.skip_ports,
        skip_bruteforce=args.skip_bruteforce,
        passive_only=args.passive_only,
        profile=args.profile,
        correlate_domains=args.correlate_domains,
        bug_hunt_mode=args.bug_hunt,
        cloud_enum=args.cloud_enum,
        metadata_analysis=args.metadata_analysis,
        image_forensics=args.image_forensics,
        social_eng=args.social_eng,
        reverse_image=args.reverse_image,
        enhanced_subdomains=args.enhanced_subdomains,
        ai_analyze=args.ai_analyze,
        github_scan=args.github_scan,
        waf_detection=args.waf_detection,
        deep_cms_analysis=args.deep_cms_analysis,
    )


if __name__ == "__main__":
    main()
