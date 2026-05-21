import logging
from typing import Dict, Any, Optional
from .http_client import get_http_client

logger = logging.getLogger(__name__)

# Common WAF signatures in headers or cookies
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status", "server: cloudflare"],
    "AWS WAF": ["x-amz-cf-id", "x-amzn-trace-id", "server: awselb"],
    "Akamai": ["akamai-origin-hop", "x-akamai-transformed", "server: akamai"],
    "Imperva": ["x-iinfo", "incap-ses", "visid_incap"],
    "F5 BIG-IP": ["bigipserver", "x-cnection", "server: big-ip"],
    "Sucuri": ["x-sucuri-id", "server: sucuri"],
    "Barracuda": ["barra_counter_session", "bn_"],
    "Citrix NetScaler": ["ns_af", "citrix_ns_id", "server: netscaler"],
}

def detect_waf(domain: str) -> Dict[str, Any]:
    """
    Detects presence of Web Application Firewall (WAF) by analyzing headers and behavior.
    """
    url = f"http://{domain}"
    results = {
        "detected": False,
        "firewall": "None",
        "method": "Passive Analysis"
    }
    
    try:
        # 1. Passive Analysis (Headers)
        http_client = get_http_client()
        response = http_client.get(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        cookies = {k.lower(): v for k, v in response.cookies.items()}
        
        # Check Headers
        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if ":" in sig:
                    # Header value check (e.g., "server: cloudflare")
                    key, val = sig.split(":")
                    if key.strip() in headers and val.strip() in headers[key.strip()]:
                        results["detected"] = True
                        results["firewall"] = waf_name
                        results["signature"] = sig
                        return results
                else:
                    # Header name check
                    if sig in headers or sig in cookies:
                        results["detected"] = True
                        results["firewall"] = waf_name
                        results["signature"] = sig
                        return results
                        
        # 2. Active Analysis (Provocation)
        # Send a benign SQL injection payload to see if it gets blocked (403/406)
        payload_url = f"{url}/?id=1' OR 1=1 --"
        provoke_response = http_client.get(payload_url, timeout=10)
        
        if provoke_response.status_code in [403, 406, 501]:
            results["detected"] = True
            results["firewall"] = "Generic WAF (Detected via Blocking)"
            results["method"] = "Active Provocation"
            
            # Check headers of the blocked response too
            blocked_headers = {k.lower(): v.lower() for k, v in provoke_response.headers.items()}
            if "server" in blocked_headers:
                results["server_header"] = blocked_headers["server"]
                
    except Exception as e:
        logger.error(f"WAF detection failed: {e}")
        results["error"] = str(e)
        
    return results
