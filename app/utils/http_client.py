from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import requests

DEFAULT_TIMEOUT = 10
DEFAULT_HEADERS = {
    "User-Agent": "SentinelScan/1.0 (+defensive security assessment)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


_session = requests.Session()
_session.headers.update(DEFAULT_HEADERS)


def get_session() -> requests.Session:
    return _session


def fetch_page(url: str, timeout: int = DEFAULT_TIMEOUT) -> requests.Response:
    return _session.get(url, timeout=timeout, allow_redirects=True)


def is_https(url: str) -> bool:
    return urlparse(url).scheme.lower() == "https"


def response_meta(response: requests.Response) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "final_url": response.url,
        "content_type": response.headers.get("Content-Type", ""),
    }
