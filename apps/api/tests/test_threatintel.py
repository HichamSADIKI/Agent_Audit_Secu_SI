"""Tests du renseignement de menace (fonction pure evaluate_flow)."""
from __future__ import annotations

from app.services import threatintel


def test_blocklisted_ip_is_critical() -> None:
    ip = next(iter(threatintel.BLOCKLIST_IPS))
    verdict = threatintel.evaluate_flow(ip, 443)
    assert verdict is not None
    assert verdict[0] == "critical"


def test_suspicious_port_is_high() -> None:
    verdict = threatintel.evaluate_flow("8.8.8.8", 4444)
    assert verdict is not None
    assert verdict[0] == "high"
    assert "Metasploit" in verdict[1]


def test_benign_flow_is_none() -> None:
    assert threatintel.evaluate_flow("8.8.8.8", 443) is None


def test_blocklist_takes_precedence_over_port() -> None:
    ip = next(iter(threatintel.BLOCKLIST_IPS))
    verdict = threatintel.evaluate_flow(ip, 80)
    assert verdict is not None and verdict[0] == "critical"
