import os
import logging
from io import BytesIO
from typing import Dict, Any, List, Optional
from PIL import Image, ExifTags
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from .http_client import get_http_client

logger = logging.getLogger(__name__)

def get_exif_data(image: Image.Image) -> Dict[str, Any]:
    """
    Extracts EXIF data from a PIL Image object.
    """
    exif_data = {}
    try:
        if hasattr(image, '_getexif'):
            exif_info = image._getexif()
            if exif_info:
                for tag, value in exif_info.items():
                    decoded = ExifTags.TAGS.get(tag, tag)
                    # Filter out binary data or very long strings to keep report clean
                    if isinstance(value, bytes):
                        if len(value) > 50:
                            value = "<binary data>"
                        else:
                            try:
                                value = value.decode()
                            except:
                                value = "<binary data>"
                    exif_data[decoded] = value
                    
        # Also check for GPS info specifically if available
        # (It's usually in the EXIF tags, but sometimes needs parsing)
        
    except Exception as e:
        logger.warning(f"Error extracting EXIF: {e}")
        
    return exif_data

def analyze_image(target: str, is_local: bool = False) -> Dict[str, Any]:
    """
    Analyzes an image for forensic data.
    Args:
        target: URL or local file path.
        is_local: Boolean indicating if target is a local file.
    """
    results = {
        "target": target,
        "format": "unknown",
        "mode": "unknown",
        "size": "unknown",
        "exif": {},
        "error": None
    }
    
    try:
        img = None
        if is_local:
            if os.path.exists(target):
                try:
                    img = Image.open(target)
                except Exception as e:
                    return {"error": f"Failed to open local image: {e}"}
            else:
                return {"error": "File not found"}
        else:
            # Remote URL
            try:
                response = get_http_client().get(target, timeout=10, stream=True)
                response.raise_for_status()
                img = Image.open(BytesIO(response.content))
            except Exception as e:
                return {"error": f"Failed to download image: {e}"}
        
        if img:
            results["format"] = img.format
            results["mode"] = img.mode
            results["size"] = f"{img.width}x{img.height}"
            results["exif"] = get_exif_data(img)
            
    except Exception as e:
        results["error"] = str(e)
        
    return results

def find_images(domain: str) -> List[str]:
    """
    Scrapes a domain to find interesting images (e.g., high res, original photos).
    """
    images = []
    try:
        url = f"http://{domain}"
        response = get_http_client().get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for img in soup.find_all('img'):
            src = img.get('src')
            if src:
                full_url = urljoin(url, src)
                # Filter for likely photos (jpg, jpeg, png, heic)
                if any(ext in full_url.lower() for ext in ['.jpg', '.jpeg', '.png', '.heic', '.tiff']):
                    images.append(full_url)
                    
        # Return unique list, limited to top 20 to avoid overwhelming
        return list(set(images))[:20]
        
    except Exception as e:
        logger.warning(f"Failed to scrape images from {domain}: {e}")
        return []
