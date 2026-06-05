from __future__ import annotations

from urllib.parse import urljoin, urlparse


ALLOWED_SCHEMES = {"http", "https"}


def normalize_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme:
        value = f"https://{value}"
        parsed = urlparse(value)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Only http and https URLs are supported")
    if not parsed.netloc:
        raise ValueError("URL must include a network location")
    return value


def same_domain(base_url: str, candidate_url: str) -> bool:
    return urlparse(base_url).netloc.lower() == urlparse(candidate_url).netloc.lower()


def safe_join(base_url: str, path: str) -> str:
    return urljoin(base_url, path)
