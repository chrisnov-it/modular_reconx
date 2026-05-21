# modules/vuln_scanner.py (Final Version with Local Database)
import os
import logging
import sqlite3
from typing import Dict, Any, List

from .utils import get_resource_path
from .http_client import get_http_client

logger = logging.getLogger(__name__)

DB_PATH = get_resource_path("data/vulnerabilities.db")
VULNERS_API_URL = "https://vulners.com/api/v3/search/bulletin/"
# We still prepare search_general_vulnerabilities as a backup
VULNERS_LUCENE_API_URL = "https://vulners.com/api/v3/search/lucene/"


def _get_vulners_api_key() -> str:
    """Helper to get Vulners API key from environment variables."""
    return os.getenv("VULNERS_API_KEY", "")


def _query_local_database(technologies: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Search for vulnerabilities in the local SQLite database first.
    """
    if not os.path.exists(DB_PATH):
        return {
            "note": "Local vulnerabilities.db database not found. Run update_db.py."
        }

    found_vulns = {}
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for tech in technologies:
        product_name = tech["name"]
        version = tech["version"]

        # Query the database for matching product and version
        cursor.execute(
            "SELECT cve_id, description, cvss_score, link FROM vulnerabilities WHERE product = ? AND version = ?",
            (product_name, version),
        )
        results = cursor.fetchall()

        if results:
            tech_key = f"{product_name}/{version}"
            found_vulns[tech_key] = []
            for row in results:
                vuln = {
                    "id": row[0],
                    "title": row[1],  # Using description as title
                    "cvss_score": row[2],
                    "href": row[3],
                    "source": "Local DB",  # Indicates this data is from the local database
                }
                found_vulns[tech_key].append(vuln)

    conn.close()
    return found_vulns


def _query_vulners_api(technologies: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Search for vulnerabilities using the Vulners API for the given technologies.
    """
    api_key = _get_vulners_api_key()
    if not api_key:
        # Do not return an error, just a note, because this is a fallback
        return {"note": "API check skipped, VULNERS_API_KEY not set."}

    vulnerabilities = {}
    for tech in technologies:
        query = f"affectedSoftware.name:{tech['name']} AND affectedSoftware.version:{tech['version']}"
        params = {"query": query, "apiKey": api_key, "size": 5}
        try:
            response = get_http_client().get(VULNERS_API_URL, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()

            if data.get("data", {}).get("total", 0) > 0:
                tech_key = f"{tech['name']}/{tech['version']}"
                vulnerabilities[tech_key] = []
                for bulletin in data.get("data", {}).get("search", []):
                    source = bulletin.get("_source", {})
                    vuln = {
                        "id": source.get("id"),
                        "title": source.get("title"),
                        "cvss_score": source.get("cvss", {}).get("score", "N/A"),
                        "href": source.get("href"),
                        "source": "Vulners API",  # Indicates this data is from the API
                    }
                    vulnerabilities[tech_key].append(vuln)
        except Exception as e:
            vulnerabilities[f"{tech['name']}/{tech['version']}"] = {
                "error": f"API request failed: {e}"
            }
    return vulnerabilities


def check_versioned_vulnerabilities(
    tech_info: Dict[str, List[str]], tech_stack: Dict[str, str]
) -> Dict[str, Any]:
    """
    Search for vulnerabilities: Using data from BuiltWith and Tech Stack,
    check the local database first, then fall back to the Vulners API if needed.
    """
    technologies_to_scan: List[Dict[str, str]] = []

    # --- PART 1: Parsing data from BuiltWith (as before) ---
    for category in tech_info.values():
        for tech_string in category:
            if "/" in tech_string:
                try:
                    name, rest = tech_string.split("/", 1)
                    version = rest.split(" ")[0]
                    technologies_to_scan.append(
                        {"name": name.strip().lower(), "version": version.strip()}
                    )
                except ValueError:
                    continue

    # --- PART 2 (NEW): Parsing data from Tech Stack (Generator) ---
    generator_string = tech_stack.get("generator")
    if generator_string:
        # Example: "WordPress 6.8.1" or "Joomla! 3.9.27"
        parts = generator_string.split(" ")
        if len(parts) >= 2:
            # Take the first word as the product name, and the last word as the version
            product_name = parts[0].strip().lower()
            version_number = parts[-1].strip()
            technologies_to_scan.append(
                {"name": product_name, "version": version_number}
            )
            print(
                f"  [+] Found version from generator: {product_name}/{version_number}"
            )

    # --- PART 3 (NEW): Parsing data from Tech Stack (Server) ---
    server_string = tech_stack.get("server")
    if server_string and "/" in server_string:
        # Example: "Apache/2.4.29 (Ubuntu)" or "nginx/1.18.0"
        try:
            name, rest = server_string.split("/", 1)
            version = rest.split(" ")[0]  # Take only the version part, ignore the rest
            product_name = name.strip().lower()
            technologies_to_scan.append(
                {"name": product_name, "version": version.strip()}
            )
            print(
                f"  [+] Found version from Server header: {product_name}/{version.strip()}"
            )
        except ValueError:
            pass  # Ignore if the format is not correct

    if not technologies_to_scan:
        return {
            "note": "No technologies with specific versions detected for scanning."
        }

    # --- STEP 1: Check the Local Database ---
    print("  [*] Searching for vulnerabilities in the local database...")
    local_results = _query_local_database(technologies_to_scan)
    print(
        f"  [+] Found {sum(len(v) for v in local_results.values() if isinstance(v, list))} vulnerabilities from the local database."
    )

    # --- STEP 2: Determine which technologies need to be checked via API ---
    techs_found_locally = set(local_results.keys())
    techs_for_api_scan = [
        tech
        for tech in technologies_to_scan
        if f"{tech['name']}/{tech['version']}" not in techs_found_locally
    ]

    # --- STEP 3: Fall back to Vulners API if there are unchecked technologies ---
    api_results = {}
    if techs_for_api_scan:
        print(
            f"  [*] Searching for vulnerabilities for {len(techs_for_api_scan)} other technologies via Vulners API..."
        )
        api_results = _query_vulners_api(techs_for_api_scan)
        print(
            f"  [+] Found {sum(len(v) for v in api_results.values() if isinstance(v, list))} vulnerabilities from Vulners API."
        )

    # --- STEP 4: Merge results ---
    final_results = {**local_results, **api_results}
    if not final_results or all(
        isinstance(v, dict) and ("note" in v or "error" in v)
        for v in final_results.values()
    ):
        return {
            "note": "No specific vulnerabilities found for the detected technologies."
        }

    return final_results


def search_general_vulnerabilities(keyword: str) -> Dict[str, Any]:
    """
    This function remains the same, as a general search based on keywords.
    """
    api_key = _get_vulners_api_key()
    if not api_key:
        return {"error": "VULNERS_API_KEY not set."}

    if not keyword:
        return {"note": "No keyword for general search."}

    headers = {"Content-Type": "application/json"}
    payload = {"query": keyword, "apiKey": api_key, "size": 5}

    try:
        response = get_http_client().post(
            VULNERS_LUCENE_API_URL, json=payload, headers=headers, timeout=15
        )
        response.raise_for_status()
        data = response.json()
        if data.get("result") != "OK" or not data.get("data", {}).get("search"):
            return {"note": f"No general vulnerabilities found for '{keyword}'."}

        vulnerabilities = []
        for item in data.get("data", {}).get("search", []):
            source = item.get("_source", {})
            vulnerabilities.append(
                {
                    "id": source.get("id"),
                    "title": source.get("title"),
                    "cvss_score": source.get("cvss", {}).get("score", "N/A"),
                    "href": source.get("href"),
                }
            )
        return {"results": vulnerabilities}
    except Exception as e:
        return {"error": f"API request failed: {e}"}
