import concurrent.futures
import logging
import uuid
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin
from tqdm import tqdm
from .utils import get_resource_path
from .http_client import get_http_client

logger = logging.getLogger(__name__)


def _get_404_baseline(base_url: str) -> Optional[int]:
    """
    Makes a request to a known-non-existent path to establish a baseline
    for "soft 404" pages by checking the content length.

    Args:
        base_url: The target base URL.

    Returns:
        The content length of the 404 page, or None if it can't be determined.
    """
    random_path = f"/{uuid.uuid4()}"
    test_url = urljoin(base_url, random_path)
    try:
        # We use a HEAD request to get the headers without the body.
        response = get_http_client().head(test_url, timeout=5, allow_redirects=False)
        # Return the content-length if the server provides it.
        return int(response.headers.get("Content-Length", -1))
    except (Exception, ValueError):
        # Ignore errors, we'll just proceed without a baseline.
        return None


def _check_path(
    url: str, path: str, baseline_404_size: Optional[int]
) -> Optional[Dict[str, Any]]:
    """
    Checks if a single path exists on the target server using a HEAD request.
    Filters out responses that match the baseline "soft 404" size.

    Args:
        url: The full URL to check.
        path: The path component being tested (e.g., '/admin').
        baseline_404_size: The content length of a known 404 page.

    Returns:
        A dictionary with path, status code, and content type if found, otherwise None.
    """
    try:
        response = get_http_client().head(url, timeout=5, allow_redirects=False)

        # We consider any status code other than 404 as potentially interesting.
        if response.status_code != 404:
            # If we have a baseline, check if the content length matches.
            if baseline_404_size is not None:
                current_size = int(response.headers.get("Content-Length", -1))
                if current_size == baseline_404_size:
                    return None  # This is likely a soft 404, ignore it.

            return {
                "path": path,
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type", "N/A"),
            }

    except Exception as e:
        # Log the error for debugging but don't crash the scan.
        logger.warning(f"Request failed for path '{path}' on {url}: {e}")
        return None
    return None


def bruteforce_paths(
    base_url: str,
    wordlist_path: str = get_resource_path("data/common_paths.txt"),
    workers: int = 50,
) -> Dict[str, Any]:
    """
    Bruteforces common web paths on a given base URL using a wordlist and concurrency.
    Includes a baseline check to filter out "soft 404" responses.

    Args:
        base_url: The target base URL (e.g., 'http://example.com').
        wordlist_path: Path to the path wordlist file.
        workers: Number of concurrent threads to use for requests.

    Returns:
        A dictionary containing a list of found paths and their status codes.
    """
    found_paths: List[Dict[str, Any]] = []
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            # Ensure paths start with a '/' for proper joining
            wordlist = [f"/{line.strip().lstrip('/')}" for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"Path bruteforce wordlist not found at: {wordlist_path}")
        return {"error": f"Wordlist not found at {wordlist_path}"}

    # Establish a baseline for soft 404s
    baseline_404_size = _get_404_baseline(base_url)
    if baseline_404_size is not None and baseline_404_size != -1:
        logger.info(
            f"Established soft 404 baseline with content length: {baseline_404_size}"
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_path = {
            executor.submit(
                _check_path,
                urljoin(base_url, path),
                path,
                baseline_404_size,
            )
            for path in wordlist
        }

        progress = tqdm(
            concurrent.futures.as_completed(future_to_path),
            total=len(wordlist),
            desc="Path Bruteforce",
            unit="path",
            leave=False,
        )

        for future in progress:
            if result := future.result():
                found_paths.append(result)

    return {"found": sorted(found_paths, key=lambda x: x["path"])}
