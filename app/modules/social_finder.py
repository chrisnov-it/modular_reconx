from bs4 import BeautifulSoup
from bs4.element import Tag
from typing import List, Dict
from .http_client import get_http_client


def find_social_links(domain: str) -> List[Dict[str, str]]:
    url = f"http://{domain}"
    try:
        response = get_http_client().get(
            url, timeout=10, headers={"User-Agent": "Mozilla/5.0"}
        )
        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a", href=True)

        platforms = {
            "Facebook": "facebook.com",
            "Instagram": "instagram.com",
            "Twitter / X": "twitter.com",
            "YouTube": "youtube.com",
            "TikTok": "tiktok.com",
            "LinkedIn": "linkedin.com",
            "Threads": "threads.net",
            "Pinterest": "pinterest.com",
            "Reddit": "reddit.com",
            "Telegram": "t.me",
            "Snapchat": "snapchat.com",
        }

        found = []
        seen_links = set()

        for link in links:
            # Type check to ensure we're working with a Tag object
            if isinstance(link, Tag):
                # Access href using dictionary-like access (this is the standard way in BeautifulSoup)
                href_attr = link.get("href")
                if href_attr:
                    href = str(href_attr).strip().lower()
                    for platform, identifier in platforms.items():
                        if identifier in href and href not in seen_links:
                            seen_links.add(href)
                            found.append({"platform": platform, "url": href})

        return found
    except Exception as e:
        return [{"error": str(e)}]
