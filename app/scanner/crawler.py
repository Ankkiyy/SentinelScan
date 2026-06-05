from __future__ import annotations

from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from app.utils.http_client import fetch_page


def crawl_target(url: str, limit: int = 20) -> dict:
    visited = set()
    discovered_links = []
    discovered_forms = []

    try:
        response = fetch_page(url)
        soup = BeautifulSoup(response.text, "html.parser")
        base_domain = urlparse(response.url).netloc

        for link in soup.find_all("a", href=True):
            absolute_url = urljoin(response.url, link["href"])
            parsed_url = urlparse(absolute_url)

            if parsed_url.scheme in {"http", "https"} and parsed_url.netloc == base_domain and absolute_url not in visited:
                visited.add(absolute_url)
                discovered_links.append(absolute_url)

            if len(discovered_links) >= limit:
                break

        for form in soup.find_all("form"):
            discovered_forms.append(
                {
                    "action": urljoin(response.url, form.get("action", "")),
                    "method": form.get("method", "GET").upper(),
                    "enctype": form.get("enctype", "application/x-www-form-urlencoded"),
                    "inputs": [
                        {
                            "name": input_tag.get("name"),
                            "type": input_tag.get("type", "text"),
                            "value": input_tag.get("value"),
                        }
                        for input_tag in form.find_all("input")
                    ],
                }
            )

        return {
            "status": "completed",
            "links_found": len(discovered_links),
            "forms_found": len(discovered_forms),
            "links": discovered_links,
            "forms": discovered_forms,
        }
    except requests.RequestException as error:
        return {
            "status": "failed",
            "error": str(error),
            "links": [],
            "forms": [],
        }
