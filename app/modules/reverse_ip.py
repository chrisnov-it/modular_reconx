import os
import shodan
import logging  # Pastikan ini diimpor
from typing import Dict, Any
from urllib.parse import urlparse
from .http_client import get_http_client

# Import ZoomEye SDK
try:
    from zoomeye.sdk import ZoomEye
except ImportError:
    ZoomEye = None

logger = logging.getLogger(__name__)  # Pastikan ini diinisialisasi


def _reverse_ip_shodan(ip: str) -> Dict[str, Any]:
    """
    Internal function to perform a reverse IP lookup using the Shodan API.
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logger.warning("Shodan API key not set. Skipping Shodan reverse IP lookup.")
        return {"source": "Shodan", "error": "Shodan API key not set."}

    try:
        api = shodan.Shodan(api_key)
        host_info = api.host(ip)

        domains = host_info.get("hostnames", []) + host_info.get("domains", [])
        unique_domains = sorted(list(set(domains)))

        if unique_domains:
            logger.info(
                f"Shodan reverse IP lookup successful for {ip}. Found {len(unique_domains)} domains."
            )
            return {"source": "Shodan", "domains": unique_domains}
        else:
            logger.info(f"Shodan found no domains for {ip}.")
            return {
                "source": "Shodan",
                "domains": [],
                "note": "No domains found via Shodan.",
            }
    except shodan.APIError as e:
        logger.error(f"Shodan API error for {ip}: {e}")
        return {"source": "Shodan", "error": f"Shodan API error: {e}"}
    except Exception as e:
        logger.error(
            f"An unexpected error occurred with Shodan for {ip}: {e}", exc_info=True
        )
        return {
            "source": "Shodan",
            "error": f"An unexpected error occurred with Shodan: {e}",
        }


def _reverse_ip_hackertarget(ip: str) -> Dict[str, Any]:
    """
    Internal function to perform a reverse IP lookup using HackerTarget API.
    """
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        response = get_http_client().get(url, timeout=10)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)

        content = response.text.strip()
        if "API count exceeded" in content or "api key" in content.lower():
            logger.warning(
                f"HackerTarget API limit exceeded or API key required for {ip}."
            )
            return {
                "source": "HackerTarget",
                "error": "API rate limit exceeded or API key required.",
            }
        elif "No records found" in content or not content:
            logger.info(f"No records found for {ip} on HackerTarget.")
            return {
                "source": "HackerTarget",
                "domains": [],
                "note": "No domains found via HackerTarget.",
            }

        domains = [
            line.strip()
            for line in content.split("\n")
            if line.strip() and not line.startswith("error")
        ]

        logger.info(
            f"HackerTarget reverse IP lookup successful for {ip}. Found {len(domains)} domains."
        )
        return {"source": "HackerTarget", "domains": sorted(list(set(domains)))}
    except Exception as e:
        logger.error(f"Network error with HackerTarget for {ip}: {e}")
        return {"source": "HackerTarget", "error": f"Network error: {e}"}
    except Exception as e:
        logger.error(
            f"An unexpected error occurred with HackerTarget for {ip}: {e}",
            exc_info=True,
        )
        return {"source": "HackerTarget", "error": f"An unexpected error occurred: {e}"}


def _reverse_ip_viewdns(ip: str) -> Dict[str, Any]:
    """
    Internal function to perform a reverse IP lookup using ViewDNS.info.
    This method scrapes the HTML, which can be fragile.
    """
    url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
    try:
        response = get_http_client().get(
            url, timeout=15, headers={"User-Agent": "OSINT-Tool"}
        )
        response.raise_for_status()

        if "No domains found on this IP address" in response.text:
            logger.info(f"No records found for {ip} on ViewDNS.")
            return {
                "source": "ViewDNS",
                "domains": [],
                "note": "No domains found via ViewDNS.",
            }

        domains_raw = []
        # A more robust solution would use BeautifulSoup here.
        # For now, we'll try to extract simple lines.
        for line in response.text.splitlines():
            # Example: <td>example.com</td>
            if "<td>" in line and "</td>" in line:
                cleaned_line = line.replace("<td>", "").replace("</td>", "").strip()
                # Basic filter to ensure it's not a header or irrelevant text
                if "." in cleaned_line and not any(
                    keyword in cleaned_line
                    for keyword in [
                        "Host Name",
                        "Date Found",
                        "Record Count",
                        "<a href",
                    ]
                ):
                    parsed_url = urlparse(f"http://{cleaned_line}")
                    if parsed_url.netloc:
                        domains_raw.append(parsed_url.netloc.lower())
                    elif cleaned_line.count(".") >= 1 and len(cleaned_line) > 3:
                        domains_raw.append(cleaned_line.lower())

        domains = sorted(list(set(domains_raw)))

        if not domains:
            logger.info(f"ViewDNS found no domains for {ip} after parsing.")
            return {
                "source": "ViewDNS",
                "domains": [],
                "note": "No domains found via ViewDNS after parsing.",
            }

        logger.info(
            f"ViewDNS reverse IP lookup successful for {ip}. Found {len(domains)} domains."
        )
        return {"source": "ViewDNS", "domains": domains}
    except Exception as e:
        logger.error(f"Network error with ViewDNS for {ip}: {e}")
        return {"source": "ViewDNS", "error": f"Network error: {e}"}
    except Exception as e:
        logger.error(
            f"An unexpected error occurred with ViewDNS for {ip}: {e}", exc_info=True
        )
        return {"source": "ViewDNS", "error": f"An unexpected error occurred: {e}"}


def _reverse_ip_zoomeye(ip: str) -> Dict[str, Any]:
    """
    Internal function to perform a reverse IP lookup using the ZoomEye API.
    """
    if ZoomEye is None:
        logger.warning(
            "ZoomEye library not installed. Skipping ZoomEye reverse IP lookup."
        )
        return {"source": "ZoomEye", "error": "ZoomEye library not installed."}

    api_key = os.getenv("ZOOMEYE_API_KEY")
    if not api_key:
        logger.warning("ZoomEye API key not set. Skipping ZoomEye reverse IP lookup.")
        return {
            "source": "ZoomEye",
            "error": "ZoomEye API key not set. Set the ZOOMEYE_API_KEY environment variable.",
        }

    try:
        api = ZoomEye(api_key=api_key)

        # Construct the query to search for the specific IP address.
        # REMOVED 'resource' parameter as it's not supported by this version's search() method.
        query = f'ip:"{ip}"'
        results = api.search(
            query, page=1, pagesize=100
        )  # Hapus 'resource='host'' di sini

        domains = []
        if results and "matches" in results:
            for match in results["matches"]:
                hostnames = match.get("hostname")
                if isinstance(hostnames, list):
                    domains.extend(hostnames)
                elif isinstance(hostnames, str) and hostnames:
                    domains.append(hostnames)

                domain_field = match.get("domain")
                if domain_field and domain_field not in domains:
                    domains.append(domain_field)

        unique_domains = sorted(list(set(domains)))

        if unique_domains:
            logger.info(
                f"ZoomEye reverse IP lookup successful for {ip}. Found {len(unique_domains)} domains."
            )
            return {"source": "ZoomEye", "domains": unique_domains}
        else:
            logger.info(f"ZoomEye found no domains for {ip}.")
            return {
                "source": "ZoomEye",
                "note": "No domains found for this IP on ZoomEye.",
            }

    except Exception as e:
        logger.error(f"An unexpected error occurred with ZoomEye for IP {ip}: {e}")
        return {
            "source": "ZoomEye",
            "error": f"An unexpected error occurred with ZoomEye: {e}",
        }


def reverse_ip_lookup(ip: str) -> Dict[str, Any]:
    """
    Finds other domains hosted on the same IP address using a fallback chain.
    """
    if not ip:
        return {"error": "Invalid IP address provided for reverse IP lookup."}

    # Try Shodan first (requires API key)
    shodan_result = _reverse_ip_shodan(ip)
    if shodan_result and "domains" in shodan_result and shodan_result["domains"]:
        return shodan_result

    # If Shodan fails or returns no domains, try HackerTarget
    hackertarget_result = _reverse_ip_hackertarget(ip)
    if (
        hackertarget_result
        and "domains" in hackertarget_result
        and hackertarget_result["domains"]
    ):
        return hackertarget_result

    # If HackerTarget fails or returns no domains, try ViewDNS
    viewdns_result = _reverse_ip_viewdns(ip)
    if viewdns_result and "domains" in viewdns_result and viewdns_result["domains"]:
        return viewdns_result

    # If ViewDNS fails or returns no domains, try ZoomEye
    zoomeye_result = _reverse_ip_zoomeye(ip)
    if zoomeye_result and "domains" in zoomeye_result and zoomeye_result["domains"]:
        return zoomeye_result

    # If all fallbacks fail, combine their errors/notes
    all_errors = []
    if "error" in shodan_result:
        all_errors.append(f"Shodan: {shodan_result['error']}")
    if "error" in hackertarget_result:
        all_errors.append(f"HackerTarget: {hackertarget_result['error']}")
    if "error" in viewdns_result:
        all_errors.append(f"ViewDNS: {viewdns_result['error']}")
    if "error" in zoomeye_result:
        all_errors.append(f"ZoomEye: {zoomeye_result['error']}")

    # If no specific errors, but no domains found
    if not all_errors:
        all_errors.append("No domains found across all sources.")

    return {
        "source": "All Fallbacks",
        "error": f"All reverse IP lookup sources failed. Details: {'; '.join(all_errors)}",
        "domains": [],
    }
