from __future__ import annotations

from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urlparse

import requests

from app.utils.http_client import is_https


def _parse_not_after(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def check_ssl_tls(url: str) -> dict:
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {
            "status": "failed",
            "error": "Target URL does not include a hostname",
            "findings": [],
        }

    if not is_https(url):
        findings.append(
            {
                "name": "Target does not use HTTPS",
                "severity": "High",
                "description": "The supplied target URL is not HTTPS, so transport security is not enforced.",
                "evidence": f"URL: {url}",
                "recommendation": "Serve the application over HTTPS and redirect HTTP traffic to the secure endpoint.",
            }
        )

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                certificate = tls_sock.getpeercert()
                protocol_version = tls_sock.version() or "Unknown"
                cipher_name = tls_sock.cipher()[0] if tls_sock.cipher() else "Unknown"

        not_after = certificate.get("notAfter") if certificate else None
        if not_after:
            expiry = _parse_not_after(not_after)
            if expiry is not None:
                now = datetime.now(timezone.utc)
                days_remaining = (expiry - now).days
                if days_remaining < 0:
                    findings.append(
                        {
                            "name": "Expired TLS certificate",
                            "severity": "Critical",
                            "description": "The server certificate is expired.",
                            "evidence": f"Certificate expired at {not_after}",
                            "recommendation": "Renew and deploy a valid certificate immediately.",
                        }
                    )
                elif days_remaining <= 14:
                    findings.append(
                        {
                            "name": "TLS certificate expires soon",
                            "severity": "Medium",
                            "description": "The server certificate is nearing expiration.",
                            "evidence": f"Certificate expires at {not_after}",
                            "recommendation": "Renew the certificate before it expires.",
                        }
                    )

        if protocol_version in {"TLSv1", "TLSv1.1"}:
            findings.append(
                {
                    "name": "Weak TLS protocol version",
                    "severity": "High",
                    "description": f"The server negotiated {protocol_version}.",
                    "evidence": f"Protocol: {protocol_version}",
                    "recommendation": "Disable legacy TLS versions and require TLS 1.2 or newer.",
                }
            )

        if any(term in cipher_name.upper() for term in ("RC4", "3DES", "DES", "MD5", "NULL")):
            findings.append(
                {
                    "name": "Weak TLS cipher suite",
                    "severity": "High",
                    "description": "The negotiated cipher suite appears weak or deprecated.",
                    "evidence": f"Cipher: {cipher_name}",
                    "recommendation": "Prefer modern AEAD cipher suites such as AES-GCM or ChaCha20-Poly1305.",
                }
            )

        return {
            "status": "completed",
            "hostname": hostname,
            "protocol": protocol_version,
            "cipher": cipher_name,
            "findings": findings,
        }
    except (requests.RequestException, OSError, ssl.SSLError) as error:
        return {
            "status": "failed",
            "error": str(error),
            "findings": findings,
        }
