"""
HTTP Client Module for Modular ReconX
Provides enhanced security and privacy features including proxy support and user-agent rotation
"""

import requests
import random
import time
import logging
import threading
from typing import Dict, List, Optional, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# User agent list for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36",
    "Modular-ReconX/1.1 (Security Research Tool)",
]

# Default headers
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

class HTTPClient:
    """Enhanced HTTP client with privacy and security features"""
    
    def __init__(self, 
                 proxy: Optional[str] = None,
                 user_agent: Optional[str] = None,
                 rate_limit: float = 0.0,
                 timeout: int = 10,
                 max_retries: int = 3):
        """
        Initialize HTTP client with privacy and security features
        
        Args:
            proxy: Proxy URL (e.g., http://127.0.0.1:8080)
            user_agent: Specific user agent to use
            rate_limit: Minimum delay between requests in seconds
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.proxy = proxy
        self.user_agent = user_agent
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_retries = max_retries
        self.last_request_time = 0
        self._request_lock = threading.Lock()
        
        # Create session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
    def _get_headers(self) -> Dict[str, str]:
        """Get headers with user agent rotation"""
        headers = DEFAULT_HEADERS.copy()
        if self.user_agent:
            headers["User-Agent"] = self.user_agent
        else:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        return headers
        
    def _get_proxies(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration"""
        if not self.proxy:
            return None
        return {
            "http": self.proxy,
            "https": self.proxy
        }
        
    def _rate_limit(self) -> None:
        """Enforce rate limiting"""
        if self.rate_limit <= 0:
            return
            
        time_since_last = time.time() - self.last_request_time
        if time_since_last < self.rate_limit:
            sleep_time = self.rate_limit - time_since_last
            time.sleep(sleep_time)
            
    def get(self, url: str, **kwargs) -> requests.Response:
        """
        Perform GET request with privacy features
        
        Args:
            url: Target URL
            **kwargs: Additional arguments to pass to requests.get()
            
        Returns:
            Response object
        """
        with self._request_lock:
            self._rate_limit()

            # Set default parameters
            if "timeout" not in kwargs:
                kwargs["timeout"] = self.timeout
            if "headers" not in kwargs:
                kwargs["headers"] = self._get_headers()
            if "proxies" not in kwargs:
                kwargs["proxies"] = self._get_proxies()

            logger.debug(f"Making GET request to {url}")
            response = self.session.get(url, **kwargs)
            self.last_request_time = time.time()

            return response
        
    def head(self, url: str, **kwargs) -> requests.Response:
        """
        Perform HEAD request with privacy features
        
        Args:
            url: Target URL
            **kwargs: Additional arguments to pass to requests.head()
            
        Returns:
            Response object
        """
        with self._request_lock:
            self._rate_limit()

            # Set default parameters
            if "timeout" not in kwargs:
                kwargs["timeout"] = self.timeout
            if "headers" not in kwargs:
                kwargs["headers"] = self._get_headers()
            if "proxies" not in kwargs:
                kwargs["proxies"] = self._get_proxies()

            logger.debug(f"Making HEAD request to {url}")
            response = self.session.head(url, **kwargs)
            self.last_request_time = time.time()

            return response
        
    def post(self, url: str, **kwargs) -> requests.Response:
        """
        Perform POST request with privacy features
        
        Args:
            url: Target URL
            **kwargs: Additional arguments to pass to requests.post()
            
        Returns:
            Response object
        """
        with self._request_lock:
            self._rate_limit()

            # Set default parameters
            if "timeout" not in kwargs:
                kwargs["timeout"] = self.timeout
            if "headers" not in kwargs:
                kwargs["headers"] = self._get_headers()
            if "proxies" not in kwargs:
                kwargs["proxies"] = self._get_proxies()

            logger.debug(f"Making POST request to {url}")
            response = self.session.post(url, **kwargs)
            self.last_request_time = time.time()

            return response

# Global HTTP client instance for modules to use
_http_client = None

def get_http_client() -> HTTPClient:
    """
    Get global HTTP client instance
    
    Returns:
        HTTPClient instance
    """
    global _http_client
    if _http_client is None:
        _http_client = HTTPClient()
    return _http_client

def configure_http_client(proxy: Optional[str] = None,
                         user_agent: Optional[str] = None,
                         rate_limit: float = 0.0,
                         timeout: int = 10,
                         max_retries: int = 3) -> None:
    """
    Configure global HTTP client with privacy settings
    
    Args:
        proxy: Proxy URL (e.g., http://127.0.0.1:8080)
        user_agent: Specific user agent to use
        rate_limit: Minimum delay between requests in seconds
        timeout: Request timeout in seconds
        max_retries: Maximum number of retry attempts
    """
    global _http_client
    _http_client = HTTPClient(
        proxy=proxy,
        user_agent=user_agent,
        rate_limit=rate_limit,
        timeout=timeout,
        max_retries=max_retries
    )
