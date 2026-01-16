"""
Centralized HTTP client for all scanner requests.
Handles timeouts, error handling, and rate limiting.
"""

import requests
from urllib.parse import urlparse


def validate_url(url: str) -> tuple[bool, str]:
    
    if not url.strip():
        return False, "URL cannot be empty"
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "URL must use HTTP or HTTPS"
    return True, url


class HTTPClient:
    """Centralized HTTP client with safety features."""

    DEFAULT_TIMEOUT = 10
    DEFAULT_USER_AGENT = "SecurityScanner/1.0 (Educational Purpose)"

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.DEFAULT_USER_AGENT
        })

    def get(self, url: str):
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            print(f"Timeout occurred for URL: {url}")
        except requests.exceptions.ConnectionError:
            print(f"Connection error occurred for URL: {url}")
        except requests.exceptions.RequestException as e:
            print(f"Request exception for URL: {url} - {e}")
        return None

    def head(self, url: str):
        try:
            response = self.session.head(url, timeout=self.timeout)
            return response  # Return response regardless of status code
        except requests.exceptions.Timeout:
            print(f"Timeout occurred for URL: {url}")
        except requests.exceptions.ConnectionError:
            print(f"Connection error occurred for URL: {url}")
        except requests.exceptions.RequestException as e:
            print(f"Request exception for URL: {url} - {e}")
        return None

    def get_headers_only(self, url: str) -> dict | None:
        response = self.get(url)
        if response:
            return response.headers
        return None
