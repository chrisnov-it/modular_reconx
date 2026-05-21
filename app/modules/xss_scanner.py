
import urllib.parse
import random
import string
import logging
from typing import Dict, Any, List
from .http_client import get_http_client

logger = logging.getLogger(__name__)

def generate_polyglot() -> str:
    """
    Generate a safe, random polyglot string to test reflection.
    We avoid aggressive payloads to respect WAFs and safe scanning policies.
    Format: RanDomStr<"'>
    """
    rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    # We test for breaking out of HTML tag context, attribute context, and script context
    return f"{rand_str}<\"'>"

def scan_param_xss(url: str, param: str, original_params: Dict) -> Dict[str, Any]:
    """Test a single parameter for reflected reflection."""
    payload = generate_polyglot()
    
    # Construct params with payload
    test_params = original_params.copy()
    test_params[param] = payload # Replace value with payload
    
    result = {
        "parameter": param,
        "vulnerable": False,
        "reflected": False,
        "context": []
    }
    
    try:
        # We assume GET for now as it's the most common for Reflected XSS from links
        # Using a specialized User-Agent to identify the scan
        headers = {'User-Agent': 'ModularReconX-BugHunt/1.0'}
        resp = get_http_client().get(
            url, params=test_params, headers=headers, timeout=10
        )
        
        # Check reflection
        if payload in resp.text:
            result["reflected"] = True
            result["vulnerable"] = True # Basic reflection confirmed
            result["context"].append("Raw payload reflected")
        else:
            # Check partial reflection (maybe some chars were encoded)
            # 1. Check if the random string is there at least
            plain_payload = payload[:-4] # Remove <"'>
            if plain_payload in resp.text:
                result["reflected"] = True
                
                # Now lets see which dangerous chars survived
                survived = []
                if f"{plain_payload}<" in resp.text: survived.append("<")
                if f"{plain_payload}\"" in resp.text: survived.append("\"")
                if f"{plain_payload}'" in resp.text: survived.append("'")
                if f"{plain_payload}>" in resp.text: survived.append(">")
                
                if survived:
                    result["vulnerable"] = True
                    result["context"].append(f"Unsanitized chars: {', '.join(survived)}")
                else:
                    result["context"].append("Payload reflected but sanitized (Safe)")

    except Exception as e:
        logger.error(f"XSS Scan Error for {param}: {e}")
        
    return result

def scan_xss(base_url: str) -> Dict[str, Any]:
    """
    Main entry point for Reflected XSS Scanner.
    Parses URL parameters and fuzzes them one by one.
    """
    print(f"[*] Starting Reflected XSS Fuzzing on {base_url}...")
    
    results = {
        "url": base_url,
        "vulnerabilities": [],
        "scanned_params": []
    }
    
    # Parse URL
    parsed = urllib.parse.urlparse(base_url)
    params = urllib.parse.parse_qs(parsed.query)
    
    # Flatten params (parse_qs returns lists)
    flat_params = {k: v[0] for k, v in params.items()}
    
    if not flat_params:
         print("[-] No URL parameters found to fuzz.")
         return results

    # Reconstruct base URL without query
    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    print(f"[*] Fuzzing {len(flat_params)} parameters...")
    
    for param_name in flat_params:
        scan_res = scan_param_xss(clean_url, param_name, flat_params)
        results["scanned_params"].append(param_name)
        
        if scan_res["vulnerable"]:
            print(f"  [!] POTENTIAL XSS Reflected on parameter: {param_name}")
            print(f"      Context: {', '.join(scan_res['context'])}")
            results["vulnerabilities"].append(scan_res)
            
    if not results["vulnerabilities"]:
        print("[+] No obvious XSS reflections found.")
        
    return results
