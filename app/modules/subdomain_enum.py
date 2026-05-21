import dns.resolver  # For more robust DNS resolution
import dns.exception  # For specific DNS exceptions
import concurrent.futures
import logging
import uuid  # For generating random subdomains for wildcard detection
from typing import List, Dict, Optional, Any
from tqdm import tqdm
from .utils import get_resource_path  # Assuming this utility is still needed

logger = logging.getLogger(__name__)


def _resolve_subdomain(
    subdomain: str, record_types: Optional[List[str]] = None
) -> Optional[Dict[str, Any]]:
    """
    Resolves a single subdomain to its IP addresses (IPv4 and IPv6) and CNAME if any.

    Args:
        subdomain: The full subdomain string (e.g., 'www.example.com').

    Returns:
        A dictionary with the subdomain, list of IPs, and CNAME (if found), otherwise None.
    """
    if record_types is None:
        record_types = ["A", "AAAA", "CNAME"]

    wanted = {record_type.upper() for record_type in record_types}
    ips: List[str] = []
    cname: Optional[str] = None
    mx_records: List[str] = []

    # Use a try-except block for overall DNS resolution, catching specific DNS errors
    try:
        if "A" in wanted:
            try:
                a_answers = dns.resolver.resolve(
                    subdomain, "A", lifetime=2
                )  # Shorter lifetime for quicker detection of timeouts
                ips.extend([str(r) for r in a_answers])
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass  # No A record, but could still have other records
            except dns.resolver.Timeout:
                logger.debug(f"DNS resolution timed out for A record of {subdomain}")
            except dns.exception.DNSException as e:
                logger.debug(f"DNS error for A record of {subdomain}: {e}")

        if "AAAA" in wanted:
            try:
                aaaa_answers = dns.resolver.resolve(subdomain, "AAAA", lifetime=2)
                ips.extend([str(r) for r in aaaa_answers])
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass  # No AAAA record
            except dns.resolver.Timeout:
                logger.debug(f"DNS resolution timed out for AAAA record of {subdomain}")
            except dns.exception.DNSException as e:
                logger.debug(f"DNS error for AAAA record of {subdomain}: {e}")

        if "CNAME" in wanted:
            try:
                cname_answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=2)
                if cname_answers:
                    cname = str(cname_answers[0])  # Get the first CNAME target
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass  # No CNAME record
            except dns.resolver.Timeout:
                logger.debug(f"DNS resolution timed out for CNAME record of {subdomain}")
            except dns.exception.DNSException as e:
                logger.debug(f"DNS error for CNAME record of {subdomain}: {e}")

        if "MX" in wanted:
            try:
                mx_answers = dns.resolver.resolve(subdomain, "MX", lifetime=2)
                mx_records.extend([r.to_text() for r in mx_answers])
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except dns.resolver.Timeout:
                logger.debug(f"DNS resolution timed out for MX record of {subdomain}")
            except dns.exception.DNSException as e:
                logger.debug(f"DNS error for MX record of {subdomain}: {e}")

        if ips or cname or mx_records:
            result = {
                "subdomain": subdomain,
                "ips": sorted(list(set(ips))),
                "cname": cname,
            }
            if mx_records:
                result["mx"] = sorted(list(set(mx_records)))
            return result

        # If no A, AAAA, or CNAME records were found after trying all, it probably doesn't exist.
        return None
    except Exception as e:
        logger.warning(
            f"An unexpected error occurred during DNS resolution for {subdomain}: {e}"
        )
        return None


def enumerate_subdomains(
    domain: str,
    wordlist_path: str = get_resource_path("data/subdomains.txt"),
    workers: int = 50,
    use_enhanced_wordlist: bool = False,
    record_types: Optional[List[str]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Enumerates subdomains for a given domain using a wordlist and concurrency.
    Includes wildcard DNS detection to reduce false positives.

    Args:
        domain: The target domain (e.g., 'example.com').
        wordlist_path: Path to the subdomain wordlist file.
        workers: Number of concurrent threads to use for DNS resolution.
        use_enhanced_wordlist: Whether to use the larger wordlist.
        record_types: DNS record types to query. Defaults to A, AAAA, and CNAME.

    Returns:
        A dictionary containing a list of found subdomains, each with its IP(s) and CNAME.
    """
    
    # Use enhanced wordlist if requested
    if use_enhanced_wordlist:
        wordlist_path = get_resource_path("data/subdomains_enhanced.txt")
    
    found_subdomains: List[Dict[str, Any]] = []

    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"Subdomain wordlist not found at: {wordlist_path}")
        return {"error": f"Wordlist not found at {wordlist_path}"}
    except Exception as e:
        logger.error(f"Error reading wordlist {wordlist_path}: {e}")
        return {"error": f"Error reading wordlist: {e}"}

    # --- Wildcard DNS Detection ---
    wildcard_ips: List[str] = []
    random_sub = f"nonexistent-{uuid.uuid4().hex[:8]}.{domain}"
    logger.info(f"Checking for wildcard DNS using: {random_sub}")
    wildcard_result = _resolve_subdomain(random_sub, record_types)
    if wildcard_result and wildcard_result.get("ips"):
        wildcard_ips = wildcard_result["ips"]
        logger.info(f"Detected potential wildcard IPs: {', '.join(wildcard_ips)}")
    else:
        logger.info(
            "No wildcard DNS detected or random subdomain did not resolve to an IP."
        )

    subdomains_to_check = [f"{word}.{domain}" for word in wordlist]

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_subdomain = {
            executor.submit(_resolve_subdomain, sub, record_types): sub for sub in subdomains_to_check
        }

        progress = tqdm(
            concurrent.futures.as_completed(future_to_subdomain),
            total=len(subdomains_to_check),
            desc="Subdomain Scan",
            unit="doms",
            leave=False,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]",
        )  # Improved progress bar

        for future in progress:
            result = future.result()
            if result:
                subdomain_name = result["subdomain"]
                resolved_ips = result.get("ips", [])

                # Check if this is a wildcard entry
                is_wildcard = False
                if wildcard_ips:
                    # If the resolved IPs are a subset of or identical to the wildcard IPs, it's likely a wildcard.
                    # This check is more robust than simple equality.
                    if set(resolved_ips).issubset(set(wildcard_ips)) and resolved_ips:
                        is_wildcard = True

                if not is_wildcard:
                    found_subdomains.append(result)
                    logger.debug(
                        f"Found subdomain: {subdomain_name} -> IPs: {resolved_ips}, CNAME: {result.get('cname')}"
                    )
                else:
                    logger.debug(
                        f"Skipping wildcard subdomain: {subdomain_name} (resolved to {resolved_ips})"
                    )

    # Sort found subdomains alphabetically for consistent output
    found_subdomains.sort(key=lambda x: x["subdomain"])

    logger.info(
        f"Subdomain enumeration completed for {domain}. Found {len(found_subdomains)} unique subdomains."
    )
    return {"found": found_subdomains}
