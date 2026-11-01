# modules/cache.py

import json
import os
import hashlib
import time
from typing import Any, Optional
from functools import wraps

# Cache directory
CACHE_DIR = "cache"
# Default cache timeout (24 hours)
DEFAULT_TIMEOUT = 86400


def _get_cache_path(key: str) -> str:
    """Generate cache file path from key."""
    # Create cache directory if it doesn't exist
    os.makedirs(CACHE_DIR, exist_ok=True)

    # Generate filename from hash of key
    key_hash = hashlib.md5(key.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"{key_hash}.json")


def _is_cache_valid(cache_file: str, timeout: int) -> bool:
    """Check if cache file is still valid based on timeout."""
    if not os.path.exists(cache_file):
        return False

    # Check if file is older than timeout
    file_age = time.time() - os.path.getmtime(cache_file)
    return file_age < timeout


def get_cache(key: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[Any]:
    """
    Retrieve data from cache if it exists and is still valid.

    Args:
        key: Cache key
        timeout: Cache timeout in seconds (default: 24 hours)

    Returns:
        Cached data or None if not found or expired
    """
    cache_file = _get_cache_path(key)

    if not _is_cache_valid(cache_file, timeout):
        return None

    try:
        with open(cache_file, "r") as f:
            data = json.load(f)
        return data
    except (json.JSONDecodeError, IOError):
        # If there's an error reading the cache, treat it as invalid
        return None


def set_cache(key: str, data: Any) -> None:
    """
    Store data in cache.

    Args:
        key: Cache key
        data: Data to cache
    """
    cache_file = _get_cache_path(key)

    try:
        with open(cache_file, "w") as f:
            json.dump(data, f)
    except IOError:
        # If we can't write to cache, just silently fail
        pass


def cache_result(timeout: int = DEFAULT_TIMEOUT):
    """
    Decorator to cache function results.

    Args:
        timeout: Cache timeout in seconds (default: 24 hours)
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            key = f"{func.__name__}:{hashlib.md5(str(args).encode() + str(kwargs).encode()).hexdigest()}"

            # Try to get from cache first
            cached_result = get_cache(key, timeout)
            if cached_result is not None:
                return cached_result

            # If not in cache, call function and cache result
            result = func(*args, **kwargs)
            set_cache(key, result)
            return result

        return wrapper

    return decorator


def clear_cache() -> None:
    """Clear all cache files."""
    if os.path.exists(CACHE_DIR):
        for filename in os.listdir(CACHE_DIR):
            file_path = os.path.join(CACHE_DIR, filename)
            try:
                os.remove(file_path)
            except OSError:
                pass
