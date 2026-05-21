import os
import logging
from typing import List, Dict, Any
from .http_client import get_http_client


def search_vulnerabilities(software_name: str) -> List[Dict[str, Any]]:
    """
    Searches the Vulners API for vulnerabilities related to a given software name.
    Returns a list of vulnerabilities. Returns a list with an error dict on failure.
    """
    api_key = os.getenv("VULNERS_API_KEY")
    if not api_key:
        logging.warning(
            "VULNERS_API_KEY environment variable not set. Skipping vulnerability search."
        )
        return [{"error": "Vulners API key is not configured."}]

    if not software_name:
        return []  # Nothing to search for, return empty list

    headers = {"Content-Type": "application/json"}
    payload = {
        "query": software_name,
        "apiKey": api_key,
        "size": 5,  # Limit to 5 results per query for brevity
    }

    try:
        response = get_http_client().post(
            "https://vulners.com/api/v3/search/lucene/",
            json=payload,
            headers=headers,
            timeout=15,
        )
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)

        data = response.json()
        if data.get("result") != "OK" or not data.get("data", {}).get("search"):
            return []  # Return empty list if API result is not OK or no search results

        vulnerabilities = []
        for item in data.get("data", {}).get("search", []):
            source = item.get("_source", {})  # Vulners data is nested in _source
            vuln = {
                "id": source.get("id"),
                "title": source.get("title"),
                "cvss_score": source.get("cvss", {}).get("score", 0.0),
                "published": source.get("published"),
                "href": source.get("href"),
            }
            vulnerabilities.append(vuln)
        return vulnerabilities

    except Exception as e:
        logging.error(f"Error connecting to Vulners API: {e}")
        return [{"error": f"Could not connect to Vulners API: {e}"}]
