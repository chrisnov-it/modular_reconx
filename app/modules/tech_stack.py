# modules/tech_stack.py (Versi Upgrade)
from bs4 import BeautifulSoup
from typing import Dict, Any
from .http_client import get_http_client


def get_tech_stack(url: str) -> Dict[str, Any]:
    try:
        r = get_http_client().get(
            url, timeout=10, headers={"User-Agent": "Modular-ReconX/1.0"}
        )
        headers = r.headers
        soup = BeautifulSoup(r.text, "html.parser")

        # Mencari meta tag "generator"
        generator_tag = soup.find("meta", attrs={"name": "generator"})
        generator_content = (
            generator_tag["content"] if generator_tag else "Not specified"
        )

        # --- BARU: Deteksi Header Keamanan ---
        security_headers_to_check = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        found_security_headers = {}
        for header in security_headers_to_check:
            if header in headers:
                found_security_headers[header] = headers[header]

        return {
            "server": headers.get("Server", "Not specified"),
            "x_powered_by": headers.get("X-Powered-By", "Not specified"),
            "title": soup.title.string.strip()
            if soup.title and soup.title.string
            else "N/A",
            "generator": generator_content,
            "security_headers": found_security_headers
            or {"note": "No specific security headers found."},
        }
    except Exception as e:
        return {"error": str(e)}
