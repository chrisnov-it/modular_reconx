"""Tests for the port_scanner module.

Covers scan_ports() with mocked _scan_single_port to avoid real network I/O.
"""
from typing import Any, Optional

import pytest

from app.modules.port_scanner import scan_ports


def _mock_single_port_result(open_ports: list, banners: Optional[dict] = None) -> Any:
    """Factory for a fake _scan_single_port returning controlled results."""
    banners = banners or {}

    def _inner(ip: str, port: int, timeout: float) -> Optional[dict]:
        if port in open_ports:
            return {"port": port, "banner": banners.get(port, "test-banner")}
        return None

    return _inner


class TestScanPorts:
    def test_returns_open_ports_dict_with_string_keys(self, monkeypatch):
        """Open ports are keyed by str(port) to match report format."""
        monkeypatch.setattr(
            "app.modules.port_scanner._scan_single_port",
            _mock_single_port_result([443, 22], {443: "https/1.1", 22: "ssh"}),
        )
        result = scan_ports("127.0.0.1")
        assert result["ip"] == "127.0.0.1"
        assert result["open_ports"] == {
            "443": "https/1.1",
            "22": "ssh",
        }
        # No error key when scan succeeds
        assert "error" not in result

    def test_all_ports_closed_returns_empty_dict(self, monkeypatch):
        monkeypatch.setattr(
            "app.modules.port_scanner._scan_single_port",
            _mock_single_port_result([]),
        )
        result = scan_ports("127.0.0.1")
        assert result["open_ports"] == {}

    def test_respects_custom_ports_list(self, monkeypatch):
        """Only the provided ports are scanned (not the whole COMMON_PORTS)."""
        scanned = []

        def recording(ip, port, timeout):
            scanned.append(port)
            return {"port": port, "banner": "b"} if port in (8080,) else None

        monkeypatch.setattr(
            "app.modules.port_scanner._scan_single_port",
            recording,
        )
        scan_ports("127.0.0.1", ports=[8080, 9090])
        assert scanned == [8080, 9090]

    def test_invalid_ip_returns_error_without_scanning(self, monkeypatch):
        """Missing/empty IP short-circuits and returns an error dict."""
        monkeypatch.setattr(
            "app.modules.port_scanner._scan_single_port",
            _mock_single_port_result([443]),
        )
        result = scan_ports("")
        assert result["error"] == "Invalid IP address provided."
        assert result["open_ports"] == {}

    def test_empty_ports_list_returns_empty(self, monkeypatch):
        monkeypatch.setattr(
            "app.modules.port_scanner._scan_single_port",
            _mock_single_port_result([]),
        )
        result = scan_ports("127.0.0.1", ports=[])
        assert result["open_ports"] == {}
