import waybackpy
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


def get_wayback_urls(domain: str) -> Dict[str, Any]:
    """
    Fetches a sample of archived URLs for a domain from the Wayback Machine.

    Args:
        domain: The target domain (e.g., 'example.com').

    Returns:
        A dictionary containing a list of found URLs or an error/note.
    """
    try:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        # Use the CDX server API to get a list of snapshots, limiting to the 20 most recent.
        cdx = waybackpy.WaybackMachineCDXServerAPI(
            domain, user_agent=user_agent, limit=20
        )
        snapshots = cdx.snapshots()

        # The generator provides snapshots; we extract the unique URLs.
        urls: List[str] = sorted(
            list(set(snapshot.archive_url for snapshot in snapshots))
        )

        if not urls:
            return {"note": "No archives found for this domain."}

        return {"urls": urls, "count": len(urls)}
    except Exception as e:
        logger.warning(f"Wayback Machine lookup for {domain} failed: {e}")
        return {"error": f"An unexpected error occurred: {str(e)}"}
