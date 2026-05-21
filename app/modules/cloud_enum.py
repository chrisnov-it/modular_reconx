import concurrent.futures
import logging
from typing import Dict, List, Any
from .http_client import get_http_client

def check_url(url: str, provider: str) -> Dict[str, Any]:
    """
    Checks if a cloud storage URL is accessible.
    """
    try:
        # Set a short timeout to speed up scanning
        response = get_http_client().head(url, timeout=3, allow_redirects=True)
        if response.status_code in [200, 403]:
            # 200: Publicly accessible
            # 403: Exists but private (still a finding)
            return {
                "url": url,
                "provider": provider,
                "status": response.status_code,
                "accessible": response.status_code == 200
            }
    except Exception:
        pass
    return {}

def check_cloud_storage(domain: str) -> Dict[str, Any]:
    """
    Enumerates potential public cloud storage buckets for a given domain.
    """
    results = {
        "aws_s3": [],
        "azure_blob": [],
        "gcp_bucket": [],
        "total_found": 0
    }
    
    # Extract keyword from domain (e.g., "example" from "example.com")
    keyword = domain.split('.')[0]
    
    # Common permutations
    permutations = [
        f"{keyword}",
        f"{keyword}-dev",
        f"{keyword}-staging",
        f"{keyword}-prod",
        f"{keyword}-test",
        f"{keyword}-backup",
        f"{keyword}-assets",
        f"{keyword}-static",
        f"{keyword}-public",
        f"www-{keyword}",
        f"{keyword}-data",
        f"{keyword}-files"
    ]
    
    # Define targets
    targets = []
    for name in permutations:
        # AWS S3
        targets.append((f"http://{name}.s3.amazonaws.com", "aws_s3"))
        # Azure Blob
        targets.append((f"https://{name}.blob.core.windows.net", "azure_blob"))
        # GCP Bucket
        targets.append((f"https://storage.googleapis.com/{name}", "gcp_bucket"))

    print(f"[*] Checking {len(targets)} potential cloud storage endpoints for '{keyword}'...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(check_url, url, provider): (url, provider) for url, provider in targets}
        
        for future in concurrent.futures.as_completed(future_to_url):
            data = future.result()
            if data:
                provider = data["provider"]
                results[provider].append(data)
                results["total_found"] += 1
                
                # Print findings (no Unicode emojis for Windows compatibility)
                if data["accessible"]:
                    status_icon = "[PUBLIC]"
                else:
                    status_icon = "[PRIVATE]"
                
                print(f"  [+] Found {data['provider']}: {data['url']} ({status_icon} {data['status']})")

    return results
