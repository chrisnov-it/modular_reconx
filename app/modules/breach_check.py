import os
import logging  # Import logging module here
from typing import Dict, Any
from .http_client import get_http_client


def check_email_breach_hibp(email: str) -> Dict[str, Any]:
    """Check email breach using Have I Been Pwned API."""
    api_key = os.getenv("HIBP_API_KEY")

    headers = {
        "User-Agent": "OSINT-Tool",
    }
    if api_key:
        headers["hibp-api-key"] = api_key
    else:
        logging.error("HIBP_API_KEY is not set. Skipping breach check for %s", email)
        return {
            "email": email,
            "error": "HIBP_API_KEY is not set. An API key is required.",
        }

    try:
        response = get_http_client().get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers,
            timeout=10,
        )

        if response.status_code == 200:
            breaches = [b.get("Name") for b in response.json()]
            return {"email": email, "breached": True, "sources": breaches}
        elif response.status_code == 404:
            return {"email": email, "breached": False, "sources": []}
        elif response.status_code == 429:
            logging.warning(
                "HIBP API rate limit hit for %s. Consider implementing retry logic.",
                email,
            )
            return {
                "email": email,
                "error": f"API returned status code: {response.status_code} - Too Many Requests. Please wait and try again.",
            }
        else:
            logging.error(
                "HIBP API returned unexpected status code %d for %s: %s",
                response.status_code,
                email,
                response.text,
            )
            return {
                "email": email,
                "error": f"API returned status code: {response.status_code} - {response.text}",
            }
    except Exception as e:
        logging.error(
            "A network error occurred during HIBP check for %s: %s",
            email,
            str(e),
            exc_info=True,
        )
        return {"email": email, "error": f"A network error occurred: {str(e)}"}
    except Exception as e:
        logging.error(
            "An unexpected error occurred during HIBP check for %s: %s",
            email,
            str(e),
            exc_info=True,
        )
        return {"email": email, "error": str(e)}


def check_email_breach_mozilla(email: str) -> Dict[str, Any]:
    """Check email breach using Mozilla Monitor API (free alternative)."""
    try:
        # Mozilla Monitor API endpoint
        response = get_http_client().get(
            f"https://monitor.firefox.com/api/v1/scan/{email}",
            timeout=10,
        )
        
        if response.status_code == 200:
            data = response.json()
            breaches = data.get("breaches", [])
            if breaches:
                sources = [breach.get("Name", "Unknown") for breach in breaches]
                return {"email": email, "breached": True, "sources": sources}
            else:
                return {"email": email, "breached": False, "sources": []}
        elif response.status_code == 404:
            return {"email": email, "breached": False, "sources": []}
        else:
            logging.error(
                "Mozilla Monitor API returned unexpected status code %d for %s: %s",
                response.status_code,
                email,
                response.text,
            )
            return {
                "email": email,
                "error": f"Mozilla Monitor API returned status code: {response.status_code}",
            }
    except Exception as e:
        logging.error(
            "A network error occurred during Mozilla Monitor check for %s: %s",
            email,
            str(e),
            exc_info=True,
        )
        return {"email": email, "error": f"A network error occurred: {str(e)}"}
    except Exception as e:
        logging.error(
            "An unexpected error occurred during Mozilla Monitor check for %s: %s",
            email,
            str(e),
            exc_info=True,
        )
        return {"email": email, "error": str(e)}


def check_email_breach(email: str) -> Dict[str, Any]:
    """Main function that tries HIBP first, then falls back to Mozilla Monitor."""
    # Try HIBP first if API key is available
    hibp_result = check_email_breach_hibp(email)
    
    # If HIBP succeeded or had a recognized error, return the result
    if "breached" in hibp_result or "error" in hibp_result:
        # Check if it's an API key error, if so try the free alternative
        if "HIBP_API_KEY is not set" in hibp_result.get("error", ""):
            logging.info("Falling back to Mozilla Monitor for breach check")
            return check_email_breach_mozilla(email)
        return hibp_result
    
    # If for some reason HIBP didn't return a proper result, try Mozilla Monitor
    return check_email_breach_mozilla(email)
