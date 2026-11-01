import urllib.parse
from typing import Dict, List

def generate_reverse_links(image_url: str) -> Dict[str, str]:
    """
    Generates reverse image search links for various search engines.
    """
    encoded_url = urllib.parse.quote(image_url)
    
    links = {
        "google_lens": f"https://lens.google.com/upload?ep=ccm&s=&st={encoded_url}",
        # For Google Images (legacy), it's harder to link directly without upload, 
        # but Lens is the modern standard.
        # Alternatively: https://www.google.com/searchbyimage?image_url={encoded_url}
        "google_images": f"https://www.google.com/searchbyimage?image_url={encoded_url}",
        "bing": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIHMP&q=imgurl:{encoded_url}",
        "yandex": f"https://yandex.com/images/search?rpt=imageview&url={encoded_url}",
        "tineye": f"https://tineye.com/search?url={encoded_url}"
    }
    
    return links

def print_reverse_links(image_url: str):
    """
    Helper to print links in a readable format.
    """
    links = generate_reverse_links(image_url)
    print(f"\n[🔗] Reverse Image Search Links for: {image_url}")
    print(f"  ├── Google Images: {links['google_images']}")
    print(f"  ├── Bing Visual:   {links['bing']}")
    print(f"  ├── Yandex:        {links['yandex']}")
    print(f"  └── TinEye:        {links['tineye']}")
