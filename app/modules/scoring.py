"""
Enhanced scoring and severity assessment for bug hunt findings
"""

from typing import Dict, List, Any, Tuple
import re


class SeverityLevel:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityScorer:
    """Enhanced scoring system for security vulnerabilities"""

    def __init__(self):
        self.findings = []
        self.overall_score = 0
        self.risk_distribution = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 0,
            SeverityLevel.MEDIUM: 0,
            SeverityLevel.LOW: 0,
            SeverityLevel.INFO: 0
        }

    def analyze_bug_hunt_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze all bug hunt results and assign severity scores"""
        self.findings = []

        # Analyze each bug hunt module
        self._analyze_js_findings(results.get("js_analysis", {}))
        self._analyze_security_headers(results.get("security_headers_analysis", {}))
        self._analyze_form_findings(results.get("form_analysis", {}))
        self._analyze_cors_findings(results.get("cors_analysis", {}))
        self._analyze_clickjacking(results.get("clickjacking_analysis", {}))
        self._analyze_param_pollution(results.get("param_pollution_analysis", {}))
        self._analyze_xss_findings(results.get("xss_scan", {}))
        self._analyze_api_discovery(results.get("api_discovery", {}))
        self._analyze_advanced_findings(results.get("advanced_vuln_detection", {}))

        # Calculate overall score
        self._calculate_overall_score()

        return {
            "findings": self.findings,
            "severity_distribution": self.risk_distribution,
            "overall_score": self.overall_score,
            "risk_level": self._get_overall_risk_level(),
            "executive_summary": self._generate_executive_summary(),
            "prioritized_recommendations": self._generate_prioritized_recommendations()
        }

    def _analyze_js_findings(self, js_results: Dict[str, Any]) -> None:
        """Analyze JavaScript security findings"""
        if not js_results.get("js_files"):
            return

        for js_file in js_results["js_files"]:
            issues = js_file.get("security_issues", [])
            vulnerable_patterns = js_file.get("vulnerable_patterns", [])

            # Critical: Direct innerHTML usage
            if "Direct innerHTML assignment detected" in issues:
                self._add_finding(
                    SeverityLevel.CRITICAL,
                    "DOM XSS Vulnerability",
                    f"Direct innerHTML usage in {js_file['url']}",
                    "Immediate XSS risk - can lead to code execution",
                    ["Implement safe DOM manipulation", "Use textContent or innerText", "Sanitize user input"]
                )

            # High: Debug statements in production
            if "Debug statements found in production code" in issues:
                self._add_finding(
                    SeverityLevel.HIGH,
                    "Information Disclosure",
                    f"Debug statements in production JavaScript: {js_file['url']}",
                    "Exposes internal application logic and debugging information",
                    ["Remove console.log/debug statements", "Use proper logging framework"]
                )

            # Medium: Sensitive data exposure
            if js_file.get("sensitive_data"):
                sensitive_keys = []
                if js_file["sensitive_data"].get("api_keys"):
                    sensitive_keys.extend(js_file["sensitive_data"]["api_keys"])
                if js_file["sensitive_data"].get("urls"):
                    sensitive_keys.extend([url for url in js_file["sensitive_data"]["urls"] if "api." in url])

                if sensitive_keys:
                    self._add_finding(
                        SeverityLevel.MEDIUM,
                        "Sensitive Data Exposure",
                        f"API keys/URLs exposed in JavaScript: {js_file['url']}",
                        f"Found {len(sensitive_keys)} potentially sensitive items",
                        ["Move sensitive data to server-side", "Use environment variables", "Implement proper secrets management"]
                    )

            # Low: Library usage patterns
            for pattern in vulnerable_patterns:
                if "jquery" in pattern.lower():
                    self._add_finding(
                        SeverityLevel.LOW,
                        "Outdated Library Usage",
                        f"jQuery detected in {js_file['url']}",
                        "jQuery may have known vulnerabilities if outdated",
                        ["Update to latest jQuery version", "Consider modern alternatives like React/Vue"]
                    )

    def _analyze_security_headers(self, header_results: Dict[str, Any]) -> None:
        """Analyze security headers"""
        analysis = header_results.get("security_headers", {}).get("security_analysis", {})

        # Critical: Missing CSP
        if "content-security-policy" in analysis.get("missing_headers", {}):
            self._add_finding(
                SeverityLevel.CRITICAL,
                "Missing Content Security Policy",
                "No CSP header implemented",
                "Allows XSS attacks and unauthorized resource loading",
                ["Implement comprehensive CSP", "Use 'default-src 'self'' as minimum", "Add script-src, style-src directives"]
            )

        # High: Missing HSTS
        if "strict-transport-security" not in analysis.get("present_headers", {}):
            self._add_finding(
                SeverityLevel.HIGH,
                "Missing HSTS Header",
                "HTTP Strict Transport Security not configured",
                "Vulnerable to SSL stripping and man-in-the-middle attacks",
                ["Implement HSTS with max-age=63072000", "Add includeSubdomains and preload"]
            )

        # Medium: Missing X-Frame-Options
        if "x-frame-options" not in analysis.get("present_headers", {}):
            self._add_finding(
                SeverityLevel.MEDIUM,
                "Missing X-Frame-Options",
                "No clickjacking protection",
                "Allows clickjacking attacks",
                ["Set X-Frame-Options: DENY or SAMEORIGIN"]
            )

        # Low: Server header exposure
        if "server" in analysis.get("deprecated_headers", {}):
            self._add_finding(
                SeverityLevel.LOW,
                "Server Information Disclosure",
                f"Server header exposes: {analysis['deprecated_headers']['server']['value']}",
                "Reveals server technology information",
                ["Remove or obfuscate Server header", "Use generic server name"]
            )

    def _analyze_form_findings(self, form_results: Dict[str, Any]) -> None:
        """Analyze form security findings"""
        analysis = form_results.get("form_analysis", {})

        vulnerable_forms = analysis.get("vulnerable_forms", 0)
        if vulnerable_forms > 0:
            self._add_finding(
                SeverityLevel.HIGH,
                "Insecure Form Configuration",
                f"{vulnerable_forms} forms with security issues",
                "Forms missing CSRF protection and input validation",
                ["Implement CSRF tokens", "Add client-side validation", "Use POST for sensitive operations"]
            )

    def _analyze_cors_findings(self, cors_results: Dict[str, Any]) -> None:
        """Analyze CORS configuration"""
        analysis = cors_results.get("cors_analysis", {})

        if analysis.get("misconfigurations"):
            self._add_finding(
                SeverityLevel.MEDIUM,
                "CORS Misconfiguration",
                f"{len(analysis['misconfigurations'])} CORS issues found",
                "Improper CORS configuration can lead to data leakage",
                ["Restrict Access-Control-Allow-Origin", "Avoid wildcard origins", "Validate preflight requests"]
            )

    def _analyze_clickjacking(self, clickjacking_results: Dict[str, Any]) -> None:
        """Analyze clickjacking protection"""
        assessment = clickjacking_results.get("protection_analysis", {}).get("vulnerability_assessment", {})

        if assessment.get("vulnerable"):
            self._add_finding(
                SeverityLevel.MEDIUM,
                "Clickjacking Vulnerability",
                "Insufficient clickjacking protection",
                "Allows malicious framing of the application",
                ["Implement X-Frame-Options: DENY", "Add CSP frame-ancestors directive"]
            )

    def _analyze_param_pollution(self, pollution_results: Dict[str, Any]) -> None:
        """Analyze parameter pollution findings"""
        assessment = pollution_results.get("pollution_detection", {}).get("vulnerability_assessment", {})

        if assessment.get("vulnerable"):
            self._add_finding(
                SeverityLevel.MEDIUM,
                "HTTP Parameter Pollution",
                "Parameter pollution vulnerability detected",
                "Allows bypassing input validation and security controls",
                ["Implement strict parameter validation", "Use allowlists", "Sanitize all inputs"]
            )

    def _analyze_xss_findings(self, xss_results: Dict[str, Any]) -> None:
        """Analyze XSS scan results"""
        vulnerabilities = xss_results.get("vulnerabilities", [])

        if vulnerabilities:
            for vuln in vulnerabilities:
                self._add_finding(
                    SeverityLevel.CRITICAL,
                    "Reflected XSS Vulnerability",
                    f"XSS in parameter: {vuln.get('parameter', 'unknown')}",
                    "Allows code execution in victim's browser",
                    ["Implement output encoding", "Use CSP", "Validate and sanitize inputs"]
                )

    def _analyze_api_discovery(self, api_results: Dict[str, Any]) -> None:
        """Analyze API discovery findings"""
        endpoints = api_results.get("discovered_endpoints", [])

        if endpoints:
            sensitive_endpoints = [ep for ep in endpoints if any(keyword in ep.lower() for keyword in
                                                                 ['admin', 'config', 'debug', 'internal', 'private'])]

            if sensitive_endpoints:
                self._add_finding(
                    SeverityLevel.MEDIUM,
                    "Exposed Sensitive Endpoints",
                    f"{len(sensitive_endpoints)} potentially sensitive API endpoints found",
                    "Internal or sensitive APIs may be publicly accessible",
                    ["Implement proper authentication", "Use API gateways", "Restrict endpoint access"]
                )

    def _analyze_advanced_findings(self, advanced_results: Dict[str, Any]) -> None:
        """Analyze advanced vulnerability detection results"""
        if not advanced_results:
            return

        # Process findings from each advanced check
        for check_name, check_results in advanced_results.items():
            if check_name == "summary":
                continue

            if isinstance(check_results, dict) and "findings" in check_results:
                for finding in check_results["findings"]:
                    # Convert advanced finding to standard format
                    severity = finding.get("severity", "MEDIUM")
                    title = finding.get("title", "Advanced Vulnerability")
                    description = finding.get("description", "")
                    impact = f"Advanced {finding.get('type', 'unknown')} vulnerability detected"
                    recommendations = finding.get("recommendations", [])

                    self._add_finding(severity, title, description, impact, recommendations)

    def _add_finding(self, severity: str, title: str, description: str, impact: str, recommendations: List[str]) -> None:
        """Add a finding to the results"""
        finding = {
            "severity": severity,
            "title": title,
            "description": description,
            "impact": impact,
            "recommendations": recommendations,
            "cvss_score": self._calculate_cvss_score(severity),
            "cvss_vector": self._get_cvss_vector(severity)
        }

        self.findings.append(finding)
        self.risk_distribution[severity] += 1

    def _calculate_cvss_score(self, severity: str) -> float:
        """Calculate CVSS score based on severity"""
        scores = {
            SeverityLevel.CRITICAL: 9.8,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.5,
            SeverityLevel.LOW: 3.2,
            SeverityLevel.INFO: 1.0
        }
        return scores.get(severity, 1.0)

    def _get_cvss_vector(self, severity: str) -> str:
        """Get CVSS vector string"""
        vectors = {
            SeverityLevel.CRITICAL: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            SeverityLevel.HIGH: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            SeverityLevel.MEDIUM: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
            SeverityLevel.LOW: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
            SeverityLevel.INFO: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        }
        return vectors.get(severity, vectors[SeverityLevel.INFO])

    def _calculate_overall_score(self) -> None:
        """Calculate overall risk score"""
        weights = {
            SeverityLevel.CRITICAL: 10,
            SeverityLevel.HIGH: 7,
            SeverityLevel.MEDIUM: 4,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1
        }

        total_weighted_score = 0
        total_findings = len(self.findings)

        if total_findings == 0:
            self.overall_score = 0
            return

        for finding in self.findings:
            total_weighted_score += weights.get(finding["severity"], 1)

        # Normalize to 0-100 scale
        self.overall_score = min(100, (total_weighted_score / (total_findings * 10)) * 100)

    def _get_overall_risk_level(self) -> str:
        """Get overall risk level"""
        if self.overall_score >= 80:
            return "CRITICAL"
        elif self.overall_score >= 60:
            return "HIGH"
        elif self.overall_score >= 40:
            return "MEDIUM"
        elif self.overall_score >= 20:
            return "LOW"
        else:
            return "INFO"

    def _generate_executive_summary(self) -> str:
        """Generate executive summary"""
        critical_count = self.risk_distribution[SeverityLevel.CRITICAL]
        high_count = self.risk_distribution[SeverityLevel.HIGH]
        total_findings = len(self.findings)

        summary = f"Security assessment identified {total_findings} security findings. "

        if critical_count > 0:
            summary += f"CRITICAL: {critical_count} critical vulnerabilities require immediate attention. "
        if high_count > 0:
            summary += f"HIGH: {high_count} high-risk issues need prompt remediation. "

        summary += f"Overall risk score: {self.overall_score:.1f}/100 ({self._get_overall_risk_level()})."

        return summary

    def _generate_prioritized_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations"""
        recommendations = []

        # Group recommendations by priority
        priority_groups = {
            SeverityLevel.CRITICAL: [],
            SeverityLevel.HIGH: [],
            SeverityLevel.MEDIUM: [],
            SeverityLevel.LOW: []
        }

        for finding in self.findings:
            priority_groups[finding["severity"]].extend(finding["recommendations"])

        # Remove duplicates and prioritize
        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]:
            unique_recs = list(set(priority_groups[severity]))
            for rec in unique_recs:
                recommendations.append({
                    "priority": severity,
                    "recommendation": rec
                })

        return recommendations