import os
import logging
import json
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

try:
    import google.generativeai as genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

def _summarize_report(results: Dict[str, Any]) -> str:
    """
    Creates a concise summary of the scan results to fit within context windows.
    """
    summary = []
    
    # Target Info
    domain = results.get("domain", "Unknown")
    ip = results.get("ip_address", "Unknown")
    summary.append(f"Target: {domain} ({ip})")
    
    # Tech Stack
    tech = results.get("tech_stack", {})
    if tech:
        summary.append(f"Tech Stack: Server={tech.get('server')}, CMS={tech.get('generator')}")
    
    # Open Ports
    ports = results.get("open_ports", {}).get("open_ports", {})
    if ports:
        summary.append(f"Open Ports: {', '.join(ports.keys())}")
    
    # Subdomains
    subs = results.get("subdomains", {}).get("found", [])
    summary.append(f"Subdomains Found: {len(subs)}")
    if subs:
        summary.append(f"Sample Subdomains: {', '.join([s['subdomain'] for s in subs[:5]])}")
        
    # Vulnerabilities
    vulns = results.get("vulnerabilities", {})
    if isinstance(vulns, dict) and "note" not in vulns:
        summary.append(f"Version Vulnerabilities: {len(vulns)} found")
    
    keyword_vulns = results.get("vulnerabilities_by_keyword", {}).get("results", [])
    if keyword_vulns:
        summary.append(f"General Vulnerabilities: {len(keyword_vulns)} found")
        
    # Cloud Storage
    cloud = results.get("cloud_storage", {})
    if cloud.get("total_found", 0) > 0:
        summary.append(f"Cloud Buckets Found: {cloud['total_found']}")
        
    # WAF (if available from tech stack or future module)
    # ...
    
    return "\n".join(summary)

def analyze_report_with_ai(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sends the scan summary to Google Gemini for high-level analysis.
    """
    if not HAS_GENAI:
        return {"error": "google-generativeai library not installed."}
        
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {"note": "AI Analysis skipped. GEMINI_API_KEY not found in .env file."}
        
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro')
        
        # Prepare the prompt
        scan_summary = _summarize_report(results)
        prompt = f"""
        You are a Senior Cybersecurity Analyst. I have performed an OSINT reconnaissance scan on a target.
        Here is the summary of the findings:
        
        {scan_summary}
        
        Based on this data, please provide:
        1. An Executive Summary of the target's security posture.
        2. Top 3 Critical Risks identified (if any).
        3. Recommended Next Steps for a penetration tester.
        4. Any "Low Hanging Fruit" that should be checked first.
        
        Keep the response professional, concise, and actionable.
        """
        
        print("[*] Sending scan data to Gemini AI for analysis...")
        response = model.generate_content(prompt)
        
        return {
            "analysis": response.text,
            "model": "gemini-pro"
        }
        
    except Exception as e:
        logger.error(f"AI Analysis failed: {e}")
        return {"error": f"AI Analysis failed: {str(e)}"}
