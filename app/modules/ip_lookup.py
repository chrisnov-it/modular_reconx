import socket
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def get_ip(domain: str) -> Optional[str]:
    """
    Resolves the primary IPv4 address for a given domain.

    Args:
        domain: The domain name to look up.

    Returns:
        The IPv4 address as a string, or None if it cannot be resolved.
    """
    try:
        ip_address = socket.gethostbyname(domain)
        logger.info(f"Resolved IP for {domain}: {ip_address}")
        return ip_address
    except socket.gaierror as e:
        logger.warning(f"Could not resolve IP for domain {domain}: {e}")
        return None
    except Exception as e:
        logger.error(
            f"An unexpected error occurred during IP lookup for {domain}: {e}",
            exc_info=True,
        )
        return None
