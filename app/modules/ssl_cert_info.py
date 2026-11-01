import ssl
import socket
import logging  # Import logging module here
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger(__name__)  # Initialize logger for this module


def get_ssl_info(domain: str) -> Dict[str, Any]:
    """
    Retrieves SSL/TLS certificate information for a given domain.

    Args:
        domain: The domain name to query.

    Returns:
        A dictionary containing certificate subject, issuer, and validity dates,
        or an error message if the information cannot be retrieved.
    """
    try:
        context = ssl.create_default_context()
        # Set a slightly longer timeout for the full SSL handshake if needed, or adjust
        connection_timeout = 5  # seconds

        with socket.create_connection(
            (domain, 443), timeout=connection_timeout
        ) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert: Optional[Dict] = ssock.getpeercert()

        # Check if certificate was retrieved
        if not cert:
            return {"error": "No SSL certificate found for domain."}

        # Extract subject and issuer details
        subject_items: List[Tuple[str, str]] = []
        for item in cert.get("subject", []):
            if isinstance(item, tuple) and len(item) > 0:
                subject_items.append(item[0])
        subject = dict(subject_items)

        issuer_items: List[Tuple[str, str]] = []
        for item in cert.get("issuer", []):
            if isinstance(item, tuple) and len(item) > 0:
                issuer_items.append(item[0])
        issuer = dict(issuer_items)

        # Extract and optionally parse validity dates
        # Example: 'May 29 10:27:35 2025 GMT'
        valid_from_str = cert.get("notBefore")
        valid_to_str = cert.get("notAfter")

        # Extract Subject Alternative Names (SANs)
        # SANs are in the format: (('DNS', 'example.com'), ('DNS', '*.example.com'))
        san_entries = []
        for san in cert.get("subjectAltName", []):
            if isinstance(san, tuple) and len(san) > 1 and san[0] == "DNS":
                san_entries.append(san[1])

        info = {
            "subject": subject,
            "issuer": issuer,
            "valid_from": valid_from_str,
            "valid_to": valid_to_str,
            "subject_alt_names": san_entries,
        }
        logger.info(f"Successfully retrieved SSL certificate info for {domain}.")
        return info
    except ssl.SSLError as e:
        logger.error(f"SSL/TLS error for {domain}: {e}")
        return {"error": f"SSL/TLS error: {e}"}
    except socket.gaierror as e:
        logger.error(f"Cannot resolve domain {domain} for SSL certificate lookup: {e}")
        return {"error": f"Cannot resolve domain: {e}"}
    except socket.timeout:
        logger.error(f"SSL connection timed out for {domain} on port 443.")
        return {"error": "SSL connection timed out."}
    except (ConnectionRefusedError, socket.error) as e:
        logger.error(f"Connection error to {domain} for SSL certificate lookup: {e}")
        return {"error": f"Connection refused or network error: {e}"}
    except Exception as e:
        logger.error(
            f"An unexpected error occurred during SSL certificate lookup for {domain}: {e}",
            exc_info=True,
        )
        return {"error": f"An unexpected error occurred: {e}"}
