import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def generate_dorks(domain: str) -> Dict[str, List[str]]:
    """
    Generates Google Dorks to find employees and sensitive info.
    """
    dorks = {
        "linkedin_employees": [
            f'site:linkedin.com/in/ "{domain}"',
            f'site:linkedin.com/in/ "at {domain}"'
        ],
        "twitter_employees": [
            f'site:twitter.com "{domain}"',
            f'site:twitter.com "working at {domain}"'
        ],
        "sensitive_files": [
            f'site:{domain} ext:pdf OR ext:docx OR ext:xlsx OR ext:pptx',
            f'site:{domain} "confidential" OR "internal use only"'
        ],
        "login_pages": [
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:portal'
        ]
    }
    return dorks

def guess_email_pattern(emails: List[str]) -> Dict[str, Any]:
    """
    Analyzes a list of emails to guess the corporate email pattern.
    """
    if not emails:
        return {"pattern": "unknown", "confidence": 0.0}
        
    patterns = {
        "first.last": 0,
        "f.last": 0,
        "first": 0,
        "last": 0,
        "firstl": 0 # first + last_initial
    }
    
    total = 0
    for email in emails:
        try:
            local_part = email.split('@')[0]
            if '.' in local_part:
                parts = local_part.split('.')
                if len(parts) == 2:
                    if len(parts[0]) > 1 and len(parts[1]) > 1:
                        patterns["first.last"] += 1
                    elif len(parts[0]) == 1:
                        patterns["f.last"] += 1
            else:
                patterns["first"] += 1
            total += 1
        except:
            pass
            
    if total == 0:
        return {"pattern": "unknown", "confidence": 0.0}
        
    # Find most common pattern
    best_pattern = max(patterns, key=patterns.get)
    confidence = patterns[best_pattern] / total
    
    return {
        "pattern": best_pattern,
        "confidence": round(confidence, 2),
        "sample_size": total
    }

def perform_social_recon(domain: str, found_emails: List[str] = None) -> Dict[str, Any]:
    """
    Performs social engineering reconnaissance.
    """
    results = {
        "dorks": generate_dorks(domain),
        "email_analysis": {}
    }
    
    if found_emails:
        results["email_analysis"] = guess_email_pattern(found_emails)
    else:
        results["email_analysis"] = {"note": "No emails provided for pattern analysis."}
        
    return results
