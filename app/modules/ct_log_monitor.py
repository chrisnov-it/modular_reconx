"""
Certificate Transparency Log Monitoring Module for Modular ReconX
Enhances subdomain discovery beyond wordlist-based enumeration
"""

import json
import logging
import time
from typing import Dict, List, Any
from urllib.parse import quote_plus
from .http_client import get_http_client

logger = logging.getLogger(__name__)

# Certificate Transparency Log APIs
CT_LOG_APIS = [
    "https://crt.sh/?q={}&output=json",
    "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
]

# Alternative CT log services
ALT_CT_SERVICES = [
    {
        "name": "CertSpotter",
        "url": "https://api.certspotter.com/v1/issuances",
        "params": {"domain": "{}", "include_subdomains": "true", "expand": "dns_names"}
    },
    {
        "name": "BufferOver",
        "url": "https://dns.bufferover.run/dns?q={}",
        "params": {}
    }
]


def query_crt_sh(domain: str) -> List[str]:
    """
    Query crt.sh for certificates associated with a domain.
    
    Args:
        domain: The domain to search for
        
    Returns:
        List of subdomains found in certificates
    """
    subdomains = set()
    try:
        url = f"https://crt.sh/?q={quote_plus('.' + domain)}&output=json"
        logger.debug(f"Querying crt.sh: {url}")
        
        headers = {
            "User-Agent": "ModularReconX/1.1 (OSINT Tool)",
            "Accept": "application/json"
        }
        
        response = get_http_client().get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract subdomains from the certificate data
        for entry in data:
            # crt.sh returns name_value field with potential subdomains
            name_value = entry.get("name_value", "")
            if name_value:
                # Split by newline in case multiple domains are listed
                domains = name_value.split("\n")
                for d in domains:
                    d = d.strip().lower()
                    # Only include subdomains of our target domain
                    if d.endswith("." + domain) or d == domain:
                        subdomains.add(d)
                        
    except Exception as e:
        logger.warning(f"Error querying crt.sh for {domain}: {e}")
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing crt.sh response for {domain}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error querying crt.sh for {domain}: {e}")
        
    return list(subdomains)


def query_certspotter(domain: str) -> List[str]:
    """
    Query CertSpotter API for certificates associated with a domain.
    
    Args:
        domain: The domain to search for
        
    Returns:
        List of subdomains found in certificates
    """
    subdomains = set()
    try:
        url = "https://api.certspotter.com/v1/issuances"
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names"
        }
        
        logger.debug(f"Querying CertSpotter: {url}")
        
        headers = {
            "User-Agent": "ModularReconX/1.1 (OSINT Tool)",
            "Accept": "application/json"
        }
        
        response = get_http_client().get(url, params=params, headers=headers, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract subdomains from the certificate data
        for entry in data:
            dns_names = entry.get("dns_names", [])
            for name in dns_names:
                name = name.strip().lower()
                # Only include subdomains of our target domain
                if name.endswith("." + domain) or name == domain:
                    subdomains.add(name)
                    
    except Exception as e:
        logger.warning(f"Error querying CertSpotter for {domain}: {e}")
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing CertSpotter response for {domain}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error querying CertSpotter for {domain}: {e}")
        
    return list(subdomains)


def query_bufferover(domain: str) -> List[str]:
    """
    Query BufferOver for subdomains associated with a domain.
    
    Args:
        domain: The domain to search for
        
    Returns:
        List of subdomains found
    """
    subdomains = set()
    try:
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        logger.debug(f"Querying BufferOver: {url}")
        
        headers = {
            "User-Agent": "ModularReconX/1.1 (OSINT Tool)",
            "Accept": "application/json"
        }
        
        response = get_http_client().get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract subdomains from the response
        fdns = data.get("FDNS_A", [])
        rdns = data.get("RDNS", [])
        
        # Process FDNS_A records
        for record in fdns:
            if "," in record:
                parts = record.split(",")
                if len(parts) > 1:
                    subdomain = parts[1].strip().lower()
                    if subdomain.endswith("." + domain) or subdomain == domain:
                        subdomains.add(subdomain)
                        
        # Process RDNS records
        for record in rdns:
            if "," in record:
                parts = record.split(",")
                if len(parts) > 1:
                    subdomain = parts[1].strip().lower()
                    if subdomain.endswith("." + domain) or subdomain == domain:
                        subdomains.add(subdomain)
                        
    except Exception as e:
        logger.warning(f"Error querying BufferOver for {domain}: {e}")
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing BufferOver response for {domain}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error querying BufferOver for {domain}: {e}")
        
    return list(subdomains)


def monitor_certificate_transparency(domain: str) -> Dict[str, Any]:
    """
    Monitor Certificate Transparency logs for subdomain discovery.
    
    Args:
        domain: The domain to monitor
        
    Returns:
        Dictionary containing found subdomains and metadata
    """
    logger.info(f"Starting Certificate Transparency monitoring for {domain}")
    
    all_subdomains = set()
    results = {
        "crt_sh": [],
        "certspotter": [],
        "bufferover": [],
        "combined": []
    }
    
    # Query crt.sh
    logger.info("Querying crt.sh...")
    crt_sh_results = query_crt_sh(domain)
    results["crt_sh"] = crt_sh_results
    all_subdomains.update(crt_sh_results)
    logger.info(f"Found {len(crt_sh_results)} subdomains from crt.sh")
    
    # Small delay to be respectful to APIs
    time.sleep(1)
    
    # Query CertSpotter
    logger.info("Querying CertSpotter...")
    certspotter_results = query_certspotter(domain)
    results["certspotter"] = certspotter_results
    all_subdomains.update(certspotter_results)
    logger.info(f"Found {len(certspotter_results)} subdomains from CertSpotter")
    
    # Small delay to be respectful to APIs
    time.sleep(1)
    
    # Query BufferOver
    logger.info("Querying BufferOver...")
    bufferover_results = query_bufferover(domain)
    results["bufferover"] = bufferover_results
    all_subdomains.update(bufferover_results)
    logger.info(f"Found {len(bufferover_results)} subdomains from BufferOver")
    
    # Combine and sort results
    combined_results = sorted(list(all_subdomains))
    results["combined"] = combined_results
    
    logger.info(f"Certificate Transparency monitoring completed. Found {len(combined_results)} unique subdomains.")
    
    return {
        "domain": domain,
        "subdomains": combined_results,
        "sources": {
            "crt_sh": len(crt_sh_results),
            "certspotter": len(certspotter_results),
            "bufferover": len(bufferover_results)
        },
        "total_found": len(combined_results)
    }


def get_certificate_details(domain: str) -> Dict[str, Any]:
    """
    Get detailed certificate information for a domain.
    
    Args:
        domain: The domain to get certificate details for
        
    Returns:
        Dictionary containing certificate details
    """
    try:
        # This would typically use the existing SSL certificate module
        # For now, we'll return a placeholder with CT information
        ct_results = monitor_certificate_transparency(domain)
        
        return {
            "domain": domain,
            "certificate_transparency": ct_results,
            "note": "Full certificate details available through ssl_cert_info module"
        }
    except Exception as e:
        logger.error(f"Error getting certificate details for {domain}: {e}")
        return {
            "domain": domain,
            "error": str(e)
        }
