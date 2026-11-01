# modules/whois_lookup.py

import whois
import datetime
import logging
import re
from typing import Dict, Any, Optional, Union

# Import cache decorator
from .cache import cache_result

logger = logging.getLogger(__name__)


def _format_date(date_obj: Union[datetime.datetime, list, None]) -> Optional[str]:
    """
    Format a date object or list of dates into a string.

    Args:
        date_obj: A datetime object, list of datetime objects, or None

    Returns:
        Formatted date string or None if input is None
    """
    if not date_obj:
        return None

    # Handle list of dates
    if isinstance(date_obj, list):
        date_obj = date_obj[0] if date_obj else None

    # Format datetime object
    if isinstance(date_obj, datetime.datetime):
        return date_obj.strftime("%Y-%m-%d %H:%M:%S")

    return str(date_obj)


def _normalize_list_field(field: Union[str, list, None]) -> list:
    """
    Normalize a field that can be a string or list into a list.

    Args:
        field: A string, list, or None

    Returns:
        A list representation of the field
    """
    if isinstance(field, str):
        return [field]
    elif isinstance(field, list):
        return field
    else:
        return []


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


@cache_result(timeout=3600)  # Cache for 1 hour
def get_whois(domain: str) -> Dict[str, Any]:
    """
    Fetches WHOIS information for a given domain using the python-whois library.

    Args:
        domain: The domain to look up

    Returns:
        Dictionary containing WHOIS information or error details
    """
    # Validate domain format
    if not validate_domain(domain):
        logger.warning(f"Invalid domain format: {domain}")
        return {"error": f"Invalid domain format: {domain}"}

    try:
        # Using the whois.whois() function that matches your library
        w = whois.whois(domain)

        # Check if there's no registration date, assume record not found or empty
        if not w.creation_date:
            logger.warning(
                f"No valid WHOIS record found for {domain}. It might be available or uses a privacy service that hides all data."
            )
            return {"error": f"No valid WHOIS data returned for {domain}."}

        # Normalize email and nameserver fields
        emails = _normalize_list_field(w.get("emails"))
        name_servers = _normalize_list_field(w.get("name_servers"))

        result = {
            "domain_name": w.get("domain_name"),
            "registrar": w.get("registrar"),
            "emails": emails,
            "creation_date": _format_date(w.get("creation_date")),
            "expiration_date": _format_date(w.get("expiration_date")),
            "last_updated": _format_date(w.get("updated_date")),
            "name_servers": name_servers,
            "status": w.get("status"),
            "note": "Raw data not available with this library version.",
        }

        # Simple check for privacy services
        registrar = w.get("registrar")
        if registrar and any(
            keyword in registrar.lower()
            for keyword in ["privacy", "proxy", "domains by proxy"]
        ):
            result["note"] = "Domain appears to use WHOIS privacy protection."

        return result

    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {e}", exc_info=True)
        # Provide a more specific error message if available
        return {"error": f"WHOIS lookup failed for {domain}: {str(e)}"}
