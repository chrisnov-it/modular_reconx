"""
Advanced vulnerability detection module for bug hunting
"""

import requests
import re
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)


class AdvancedVulnerabilityDetector:
    """Advanced vulnerability detection for bug hunting"""

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ModularReconX-AdvancedVuln/1.0'
        })

    def run_all_checks(self) -> Dict[str, Any]:
        """Run all advanced vulnerability checks"""
        results = {
            "dom_xss_detection": self.detect_dom_based_xss(),
            "subdomain_takeover": self.check_subdomain_takeover(),
            "race_conditions": self.test_race_conditions(),
            "logic_flaws": self.detect_logic_flaws(),
            "advanced_findings": []
        }

        # Aggregate all findings
        all_findings = []
        for check_result in results.values():
            if isinstance(check_result, dict) and "findings" in check_result:
                all_findings.extend(check_result["findings"])

        results["summary"] = {
            "total_checks": 4,
            "vulnerabilities_found": len(all_findings),
            "critical_findings": len([f for f in all_findings if f.get("severity") == "CRITICAL"]),
            "high_findings": len([f for f in all_findings if f.get("severity") == "HIGH"])
        }

        return results

    def detect_dom_based_xss(self) -> Dict[str, Any]:
        """Detect DOM-based XSS vulnerabilities"""
        print("[*] Analyzing JavaScript for DOM-based XSS vulnerabilities...")

        findings = []

        try:
            # Get the main page
            response = self.session.get(self.base_url, timeout=self.timeout)
            response.raise_for_status()

            # Extract JavaScript URLs
            js_urls = self._extract_javascript_urls(response.text)

            dangerous_patterns = {
                "document.write": r"document\.write\s*\(",
                "document.writeln": r"document\.writeln\s*\(",
                "innerHTML_assignment": r"\.innerHTML\s*=\s*[^=]",
                "outerHTML_assignment": r"\.outerHTML\s*=\s*[^=]",
                "insertAdjacentHTML": r"insertAdjacentHTML\s*\(",
                "eval_usage": r"\beval\s*\(",
                "setTimeout_eval": r"setTimeout\s*\(\s*['\"](.*?)['\"]\s*,",
                "setInterval_eval": r"setInterval\s*\(\s*['\"](.*?)['\"]\s*,",
                "location.href_sinks": r"location\.href\s*=\s*",
                "location.hash_sinks": r"location\.(?:hash|search|pathname)\s*=\s*",
                "window.location_sinks": r"window\.location\s*=\s*"
            }

            for js_url in js_urls[:5]:  # Limit to first 5 JS files
                try:
                    js_response = self.session.get(js_url, timeout=self.timeout)
                    if js_response.status_code == 200:
                        js_content = js_response.text

                        for vuln_type, pattern in dangerous_patterns.items():
                            matches = re.findall(pattern, js_content, re.IGNORECASE)
                            if matches:
                                # Check if user input could reach these sinks
                                user_input_indicators = self._check_user_input_reachability(js_content, matches)

                                if user_input_indicators:
                                    findings.append({
                                        "type": "DOM_XSS",
                                        "severity": "HIGH" if vuln_type in ["eval_usage", "innerHTML_assignment"] else "MEDIUM",
                                        "title": f"Potential DOM-based XSS via {vuln_type}",
                                        "description": f"Found {len(matches)} instances of {vuln_type} in {js_url}",
                                        "location": js_url,
                                        "evidence": matches[:3],  # First 3 matches
                                        "user_input_reachable": user_input_indicators,
                                        "recommendations": [
                                            "Use safe DOM manipulation methods",
                                            "Implement Content Security Policy",
                                            "Validate and sanitize all user inputs",
                                            "Use libraries like DOMPurify for HTML sanitization"
                                        ]
                                    })

                except Exception as e:
                    logger.warning(f"Failed to analyze JS file {js_url}: {e}")

        except Exception as e:
            logger.error(f"DOM XSS detection failed: {e}")

        return {
            "findings": findings,
            "js_files_analyzed": len(js_urls),
            "vulnerabilities_found": len(findings)
        }

    def check_subdomain_takeover(self) -> Dict[str, Any]:
        """Check for subdomain takeover vulnerabilities"""
        print("[*] Checking for subdomain takeover vulnerabilities...")

        findings = []

        # Common takeover signatures for different services
        takeover_signatures = {
            "github": {
                "cname": ["github.io", "github.com"],
                "response_patterns": [r"There isn't a GitHub Pages site here", r"404 - Page not found"],
                "service": "GitHub Pages"
            },
            "heroku": {
                "cname": ["herokuapp.com", "herokudns.com"],
                "response_patterns": [r"No such app", r"Heroku \| No such application"],
                "service": "Heroku"
            },
            "aws_s3": {
                "cname": ["s3.amazonaws.com", "s3-website"],
                "response_patterns": [r"The specified bucket does not exist", r"404 Not Found"],
                "service": "AWS S3"
            },
            "azure": {
                "cname": ["azurewebsites.net", "cloudapp.azure.com"],
                "response_patterns": [r"404 Web Site not found", r"The resource you are looking for has been removed"],
                "service": "Azure"
            },
            "digitalocean": {
                "cname": ["domains.digitalocean.com"],
                "response_patterns": [r"Domain not found", r"404 - Page Not Found"],
                "service": "DigitalOcean"
            }
        }

        # This would need subdomain enumeration results
        # For now, we'll check if we can detect takeover patterns on the main domain
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)

            for service, config in takeover_signatures.items():
                vulnerable = False
                evidence = []

                # Check response content for takeover signatures
                for pattern in config["response_patterns"]:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerable = True
                        evidence.append(f"Response matches {service} takeover pattern: {pattern}")

                if vulnerable:
                    findings.append({
                        "type": "SUBDOMAIN_TAKEOVER",
                        "severity": "CRITICAL",
                        "title": f"Potential {config['service']} Subdomain Takeover",
                        "description": f"Domain appears to be vulnerable to {config['service']} subdomain takeover",
                        "location": self.base_url,
                        "service": config["service"],
                        "evidence": evidence,
                        "recommendations": [
                            f"Remove DNS records pointing to {config['service']}",
                            "Claim or delete the associated resource",
                            "Monitor for unauthorized DNS changes",
                            "Use domain monitoring services"
                        ]
                    })

        except Exception as e:
            logger.error(f"Subdomain takeover check failed: {e}")

        return {
            "findings": findings,
            "services_checked": len(takeover_signatures),
            "vulnerabilities_found": len(findings)
        }

    def test_race_conditions(self) -> Dict[str, Any]:
        """Test for race condition vulnerabilities"""
        print("[*] Testing for race condition vulnerabilities...")

        findings = []

        # Test common race condition scenarios
        race_tests = [
            {
                "name": "concurrent_registration",
                "description": "Test for concurrent user registration race conditions",
                "endpoint": "/register",
                "method": "POST",
                "data": {"username": "testuser", "email": "test@example.com", "password": "testpass123"}
            },
            {
                "name": "concurrent_purchase",
                "description": "Test for concurrent purchase race conditions",
                "endpoint": "/checkout",
                "method": "POST",
                "data": {"item_id": "123", "quantity": "1"}
            }
        ]

        for test in race_tests:
            try:
                # Quick check if endpoint exists
                test_url = urljoin(self.base_url, test["endpoint"])
                response = self.session.head(test_url, timeout=5)

                if response.status_code not in [404, 403]:  # Endpoint might exist
                    # Perform basic race condition test with 2 concurrent requests
                    results = self._perform_race_condition_test(test_url, test)

                    if results.get("potential_race"):
                        findings.append({
                            "type": "RACE_CONDITION",
                            "severity": "HIGH",
                            "title": f"Potential Race Condition in {test['name']}",
                            "description": test["description"],
                            "location": test_url,
                            "evidence": results.get("evidence", []),
                            "recommendations": [
                                "Implement proper locking mechanisms",
                                "Use database transactions",
                                "Implement idempotent operations",
                                "Add rate limiting",
                                "Use optimistic locking"
                            ]
                        })

            except Exception as e:
                logger.debug(f"Race condition test failed for {test['name']}: {e}")

        return {
            "findings": findings,
            "tests_performed": len(race_tests),
            "vulnerabilities_found": len(findings)
        }

    def detect_logic_flaws(self) -> Dict[str, Any]:
        """Detect business logic flaws"""
        print("[*] Analyzing for business logic flaws...")

        findings = []

        try:
            # Get main page and look for forms
            response = self.session.get(self.base_url, timeout=self.timeout)
            response.raise_for_status()

            forms = self._extract_forms(response.text)

            for form in forms:
                logic_issues = self._analyze_form_logic(form)

                if logic_issues:
                    findings.extend(logic_issues)

        except Exception as e:
            logger.error(f"Logic flaw detection failed: {e}")

        return {
            "findings": findings,
            "forms_analyzed": len(forms) if 'forms' in locals() else 0,
            "vulnerabilities_found": len(findings)
        }

    def _extract_javascript_urls(self, html_content: str) -> List[str]:
        """Extract JavaScript URLs from HTML"""
        js_urls = []

        # Find script tags
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(script_pattern, html_content, re.IGNORECASE)

        for match in matches:
            if match.startswith(('http://', 'https://', '//')):
                js_urls.append(match if match.startswith('http') else 'https:' + match)
            elif match.startswith('/'):
                js_urls.append(urljoin(self.base_url, match))
            else:
                js_urls.append(urljoin(self.base_url, match))

        return js_urls

    def _check_user_input_reachability(self, js_content: str, dangerous_matches: List[str]) -> List[str]:
        """Check if user input can reach dangerous sinks"""
        indicators = []

        # Look for user input sources
        user_input_sources = [
            r'location\.(?:href|hash|search)',
            r'document\.location',
            r'window\.location',
            r'URLSearchParams',
            r'localStorage\.getItem',
            r'sessionStorage\.getItem',
            r'document\.cookie'
        ]

        for source in user_input_sources:
            if re.search(source, js_content, re.IGNORECASE):
                indicators.append(f"User input source found: {source}")

        # Check for input validation
        validation_indicators = [
            r'\.replace\s*\(',
            r'encodeURIComponent',
            r'escape\s*\(',
            r'\.sanitize',
            r'\.validate'
        ]

        validation_present = any(re.search(pattern, js_content, re.IGNORECASE) for pattern in validation_indicators)

        if not validation_present and indicators:
            indicators.append("No input validation detected near dangerous operations")

        return indicators

    def _perform_race_condition_test(self, url: str, test_config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a basic race condition test"""
        results = {"potential_race": False, "evidence": []}

        def make_request(thread_id: int) -> Tuple[int, float]:
            start_time = time.time()
            try:
                response = self.session.post(url, data=test_config.get("data", {}), timeout=5)
                end_time = time.time()
                return response.status_code, end_time - start_time
            except:
                return 0, time.time() - start_time

        # Run 3 concurrent requests
        threads = []
        responses = []

        for i in range(3):
            thread = threading.Thread(target=lambda: responses.append(make_request(i)))
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join(timeout=10)

        # Analyze results
        if len(responses) >= 2:
            statuses = [r[0] for r in responses if r[0] != 0]
            times = [r[1] for r in responses]

            # Check for inconsistent responses
            if len(set(statuses)) > 1:
                results["potential_race"] = True
                results["evidence"].append(f"Inconsistent status codes: {statuses}")

            # Check for very close timing (potential race)
            if times and max(times) - min(times) < 0.1:  # All within 100ms
                results["potential_race"] = True
                results["evidence"].append("Requests completed in very close timing intervals")

        return results

    def _extract_forms(self, html_content: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        forms = []

        # Simple form extraction (could be enhanced)
        form_pattern = r'<form[^>]*>(.*?)</form>'
        matches = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)

        for i, form_content in enumerate(matches):
            forms.append({
                "id": i,
                "content": form_content,
                "action": re.search(r'action=["\']([^"\']*)["\']', form_content, re.IGNORECASE),
                "method": re.search(r'method=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            })

        return forms

    def _analyze_form_logic(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze form for logic flaws"""
        findings = []
        content = form.get("content", "")

        # Check for IDOR patterns
        idor_patterns = [
            r'id=\d+',
            r'user_id=\d+',
            r'account=\d+'
        ]

        for pattern in idor_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    "type": "LOGIC_FLAW",
                    "severity": "MEDIUM",
                    "title": "Potential IDOR Vulnerability",
                    "description": "Form contains predictable ID patterns that may allow IDOR attacks",
                    "location": f"Form {form['id']}",
                    "evidence": [pattern],
                    "recommendations": [
                        "Implement proper authorization checks",
                        "Use unpredictable identifiers",
                        "Validate user permissions on each request",
                        "Use UUIDs instead of sequential IDs"
                    ]
                })

        # Check for missing CSRF tokens
        if not re.search(r'csrf|token|_token', content, re.IGNORECASE):
            findings.append({
                "type": "LOGIC_FLAW",
                "severity": "MEDIUM",
                "title": "Missing CSRF Protection",
                "description": "Form appears to be missing CSRF protection tokens",
                "location": f"Form {form['id']}",
                "evidence": ["No CSRF token found in form"],
                "recommendations": [
                    "Implement CSRF tokens in all forms",
                    "Use anti-CSRF libraries",
                    "Validate token on server-side",
                    "Use SameSite cookies"
                ]
            })

        return findings


def run_advanced_vulnerability_detection(base_url: str) -> Dict[str, Any]:
    """Main entry point for advanced vulnerability detection"""
    detector = AdvancedVulnerabilityDetector(base_url)
    return detector.run_all_checks()