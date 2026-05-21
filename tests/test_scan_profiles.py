from typing import Any, Dict

import app.scan as scan_module


def _patch_common_scan_dependencies(monkeypatch, calls: Dict[str, int]) -> None:
    def record(name: str, result: Any):
        def _inner(*args, **kwargs):
            calls[name] = calls.get(name, 0) + 1
            return result

        return _inner

    monkeypatch.setattr(scan_module, "validate_domain", lambda domain: True)
    monkeypatch.setattr(scan_module, "get_ip", lambda domain: "127.0.0.1")
    monkeypatch.setattr(scan_module, "resolve_base_url", lambda domain: "https://example.com")
    monkeypatch.setattr(scan_module, "save_report", lambda results, output_format: "output/test.json")

    monkeypatch.setattr(scan_module, "get_whois", record("whois", {"emails": []}))
    monkeypatch.setattr(scan_module, "get_dns", record("dns", {"A": ["127.0.0.1"]}))
    monkeypatch.setattr(scan_module, "enumerate_subdomains", record("subdomains", {"found": []}))
    monkeypatch.setattr(scan_module, "find_social_links", record("social_links", []))
    monkeypatch.setattr(scan_module, "get_wayback_urls", record("wayback_urls", []))
    monkeypatch.setattr(scan_module, "monitor_certificate_transparency", record("ct", {"subdomains": []}))

    monkeypatch.setattr(scan_module, "get_tech_stack", record("tech_stack", {"server": "nginx"}))
    monkeypatch.setattr(scan_module, "detect_builtwith", record("builtwith", {}))
    monkeypatch.setattr(scan_module, "geoip_lookup", record("geoip", {}))
    monkeypatch.setattr(scan_module, "reverse_ip_lookup", record("reverse_ip", {"domains": []}))
    monkeypatch.setattr(scan_module, "get_ssl_info", record("ssl", {}))
    monkeypatch.setattr(scan_module, "scan_ports", record("ports", {"open_ports": {"443": "https"}}))
    monkeypatch.setattr(scan_module, "bruteforce_paths", record("paths", {"found": [{"path": "/admin"}]}))

    monkeypatch.setattr(scan_module, "check_versioned_vulnerabilities", record("versioned_vulns", {}))
    monkeypatch.setattr(scan_module, "search_general_vulnerabilities", record("keyword_vulns", {}))

    monkeypatch.setattr(scan_module, "comprehensive_param_analysis", record("param_analysis", {}))
    monkeypatch.setattr(scan_module, "comprehensive_js_analysis", record("js_analysis", {}))
    monkeypatch.setattr(scan_module, "comprehensive_api_discovery", record("api_discovery", {}))
    monkeypatch.setattr(scan_module, "comprehensive_security_analysis", record("security_headers", {}))
    monkeypatch.setattr(scan_module, "comprehensive_form_analysis", record("form_analysis", {}))
    monkeypatch.setattr(scan_module, "comprehensive_cors_analysis", record("cors_analysis", {}))
    monkeypatch.setattr(scan_module, "comprehensive_cookie_analysis", record("cookie_analysis", {}))
    monkeypatch.setattr(scan_module, "comprehensive_clickjacking_analysis", record("clickjacking", {}))
    monkeypatch.setattr(scan_module, "comprehensive_parameter_pollution_analysis", record("hpp", {}))
    monkeypatch.setattr(scan_module, "scan_xss", record("xss", {"vulnerabilities": []}))
    monkeypatch.setattr(
        scan_module,
        "run_advanced_vulnerability_detection",
        record("advanced_vuln", {"summary": {"total_checks": 0, "vulnerabilities_found": 0}}),
    )


def test_passive_profile_skips_active_modules(monkeypatch):
    calls: Dict[str, int] = {}
    _patch_common_scan_dependencies(monkeypatch, calls)

    results, _ = scan_module.scan("example.com", profile="passive")

    assert results["scan_profile"] == "passive"
    assert "base_url" not in results
    assert calls.get("tech_stack", 0) == 0
    assert calls.get("ports", 0) == 0
    assert calls.get("paths", 0) == 0
    assert calls.get("whois", 0) == 1


def test_safe_profile_skips_ports_and_bruteforce_but_runs_fingerprinting(monkeypatch):
    calls: Dict[str, int] = {}
    _patch_common_scan_dependencies(monkeypatch, calls)

    results, _ = scan_module.scan("example.com", profile="safe")

    assert results["scan_profile"] == "safe"
    assert results["base_url"] == "https://example.com"
    assert calls.get("tech_stack", 0) == 1
    assert calls.get("ports", 0) == 0
    assert calls.get("paths", 0) == 0
    assert results["open_ports"]["note"] == "Skipped in safe profile."
    assert results["paths_found"]["note"] == "Skipped in safe profile."


def test_active_profile_runs_ports_and_bruteforce(monkeypatch):
    calls: Dict[str, int] = {}
    _patch_common_scan_dependencies(monkeypatch, calls)

    results, _ = scan_module.scan("example.com", profile="active")

    assert results["scan_profile"] == "active"
    assert calls.get("ports", 0) == 1
    assert calls.get("paths", 0) == 1
    assert results["open_ports"]["open_ports"] == {"443": "https"}
    assert results["paths_found"]["found"] == [{"path": "/admin"}]


def test_bug_hunt_requires_aggressive_profile(monkeypatch):
    calls: Dict[str, int] = {}
    _patch_common_scan_dependencies(monkeypatch, calls)

    results, _ = scan_module.scan("example.com", profile="active", bug_hunt_mode=True)

    assert results["bug_hunt"]["note"] == "Skipped because --bug-hunt requires --profile aggressive."
    assert calls.get("param_analysis", 0) == 0
    assert calls.get("advanced_vuln", 0) == 0


def test_aggressive_profile_runs_bug_hunt(monkeypatch):
    calls: Dict[str, int] = {}
    _patch_common_scan_dependencies(monkeypatch, calls)

    results, _ = scan_module.scan("example.com", profile="aggressive", bug_hunt_mode=True)

    assert results["scan_profile"] == "aggressive"
    assert calls.get("param_analysis", 0) == 1
    assert calls.get("advanced_vuln", 0) == 1
    assert "security_assessment" in results
