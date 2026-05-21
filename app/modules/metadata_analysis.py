import os
import io
import logging
import waybackpy
from typing import Dict, List, Any
from pypdf import PdfReader
import docx
from .http_client import get_http_client

# Set up logging
logger = logging.getLogger(__name__)

def extract_pdf_metadata(content: bytes) -> Dict[str, Any]:
    try:
        with io.BytesIO(content) as f:
            reader = PdfReader(f)
            info = reader.metadata
            if info:
                return {k.strip('/'): v for k, v in info.items()}
    except Exception as e:
        logger.warning(f"Error extracting PDF metadata: {e}")
    return {}

def extract_docx_metadata(content: bytes) -> Dict[str, Any]:
    try:
        with io.BytesIO(content) as f:
            doc = docx.Document(f)
            core_props = doc.core_properties
            return {
                "author": core_props.author,
                "created": str(core_props.created),
                "last_modified_by": core_props.last_modified_by,
                "modified": str(core_props.modified),
                "title": core_props.title
            }
    except Exception as e:
        logger.warning(f"Error extracting DOCX metadata: {e}")
    return {}

def analyze_local_file(path: str) -> Dict[str, Any]:
    """
    Analyzes a local file (PDF, DOCX) for metadata.
    """
    results = {
        "file": path,
        "type": "unknown",
        "metadata": {},
        "error": None
    }
    
    if not os.path.exists(path):
        results["error"] = "File not found"
        return results
        
    try:
        with open(path, 'rb') as f:
            content = f.read()
            
        if path.lower().endswith('.pdf'):
            results["type"] = "pdf"
            results["metadata"] = extract_pdf_metadata(content)
        elif path.lower().endswith('.docx'):
            results["type"] = "docx"
            results["metadata"] = extract_docx_metadata(content)
        else:
            results["error"] = "Unsupported file type. Only PDF and DOCX are supported."
            
    except Exception as e:
        results["error"] = str(e)
        
    return results

def analyze_metadata(domain: str) -> Dict[str, Any]:
    """
    Searches for public documents (PDF, DOCX) and extracts metadata.
    Uses Wayback Machine to find files.
    """
    results = {
        "files_found": [],
        "metadata_summary": {
            "users": set(),
            "software": set(),
            "emails": set()
        }
    }
    
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    print(f"[*] Searching for public documents (PDF, DOCX) for {domain} via Wayback Machine...")
    
    try:
        cdx = waybackpy.WaybackMachineCDXServerAPI(domain, user_agent=user_agent)
        
        # We want to filter for specific extensions. 
        # WaybackCDXServerAPI doesn't support easy extension filtering in the wrapper directly 
        # without iterating, but we can iterate and check.
        # To avoid fetching too many, we'll iterate and stop after finding some or checking X amount.
        
        found_files = []
        limit_checks = 500
        count = 0
        
        # This might be slow if there are many snapshots. 
        # We can try to use the 'filter' argument if the library supports it, 
        # but the wrapper is simple. Let's just iterate.
        
        for snapshot in cdx.snapshots():
            count += 1
            url = snapshot.original_url.lower()
            if url.endswith(".pdf") or url.endswith(".docx"):
                found_files.append(snapshot.archive_url)
            
            if len(found_files) >= 10 or count >= limit_checks:
                break
                
        print(f"  [+] Found {len(found_files)} potential documents.")
        
        for file_url in found_files:
            try:
                print(f"  [*] Downloading and analyzing: {file_url}...")
                response = get_http_client().get(file_url, timeout=10)
                if response.status_code == 200:
                    meta = {}
                    file_type = "unknown"
                    
                    if file_url.lower().endswith(".pdf") or ".pdf" in file_url.lower(): # archive url might have query params
                        file_type = "pdf"
                        meta = extract_pdf_metadata(response.content)
                    elif file_url.lower().endswith(".docx") or ".docx" in file_url.lower():
                        file_type = "docx"
                        meta = extract_docx_metadata(response.content)
                    
                    if meta:
                        # Clean up metadata
                        clean_meta = {k: v for k, v in meta.items() if v}
                        results["files_found"].append({
                            "url": file_url,
                            "type": file_type,
                            "metadata": clean_meta
                        })
                        
                        # Aggregate interesting info
                        if "Author" in clean_meta: results["metadata_summary"]["users"].add(clean_meta["Author"])
                        if "author" in clean_meta: results["metadata_summary"]["users"].add(clean_meta["author"])
                        if "Creator" in clean_meta: results["metadata_summary"]["software"].add(clean_meta["Creator"])
                        if "Producer" in clean_meta: results["metadata_summary"]["software"].add(clean_meta["Producer"])
                        
            except Exception as e:
                logger.warning(f"Failed to process {file_url}: {e}")
                
    except Exception as e:
        logger.error(f"Metadata analysis failed: {e}")
        return {"error": str(e)}

    # Convert sets to lists for JSON serialization
    results["metadata_summary"]["users"] = list(results["metadata_summary"]["users"])
    results["metadata_summary"]["software"] = list(results["metadata_summary"]["software"])
    results["metadata_summary"]["emails"] = list(results["metadata_summary"]["emails"])
    
    return results
