import os
import logging
from typing import Dict, Any, List
from .http_client import get_http_client

logger = logging.getLogger(__name__)

def generate_github_dorks(domain: str) -> List[str]:
    """
    Generates GitHub search dorks for the domain.
    """
    base = "https://github.com/search?q="
    dorks = [
        f'{base}"{domain}"+password&type=Code',
        f'{base}"{domain}"+api_key&type=Code',
        f'{base}"{domain}"+secret&type=Code',
        f'{base}"{domain}"+aws_key&type=Code',
        f'{base}"{domain}"+config&type=Code',
        f'{base}"{domain}"+db_password&type=Code',
        f'{base}"{domain}"+dotfiles&type=Code',
    ]
    return dorks

def scan_github(domain: str) -> Dict[str, Any]:
    """
    Scans GitHub for exposed secrets using API (if token present) or returns dorks.
    """
    results = {
        "dorks": generate_github_dorks(domain),
        "api_findings": [],
        "note": "For automated scanning, set GITHUB_TOKEN in .env"
    }
    
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return results
        
    # If token exists, perform a basic search
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    print("[*] GITHUB_TOKEN found. Performing automated GitHub secret scan...")
    
    # We'll search for "domain" + "password" as a sample check
    query = f'"{domain}" password'
    url = f"https://api.github.com/search/code?q={query}&per_page=5"
    
    try:
        response = get_http_client().get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            items = data.get("items", [])
            results["api_findings"] = [
                {
                    "name": item.get("name"),
                    "html_url": item.get("html_url"),
                    "repository": item.get("repository", {}).get("full_name")
                }
                for item in items
            ]
            results["total_api_count"] = data.get("total_count", 0)
            print(f"  [+] Found {results['total_api_count']} potential secrets via API.")
        elif response.status_code == 403:
            results["error"] = "GitHub API Rate Limit Exceeded"
        else:
            results["error"] = f"GitHub API Error: {response.status_code}"
            
    except Exception as e:
        logger.error(f"GitHub scan failed: {e}")
        results["error"] = str(e)
        
    return results
