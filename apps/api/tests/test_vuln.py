"""Tests du moteur de vulnérabilités (fonctions pures)."""
from __future__ import annotations

from app.services import vuln
from app.services.vuln import PortLike


def _f(ports: list[PortLike]) -> list[dict]:
    return vuln.evaluate(ports)


# ── règles d'exposition ───────────────────────────────────────────────────────

def test_telnet_exposure_is_high() -> None:
    findings = _f([PortLike(port=23)])
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["source"] == "rule"
    assert findings[0]["cve_id"] is None


def test_redis_exposure_is_critical() -> None:
    findings = _f([PortLike(port=6379)])
    assert findings[0]["severity"] == "critical"


def test_http_exposure_is_low() -> None:
    findings = _f([PortLike(port=80)])
    assert findings[0]["severity"] == "low"


def test_ssh_without_banner_no_finding() -> None:
    # 22 n'est pas une règle d'exposition et pas de bannière → aucune vuln
    assert _f([PortLike(port=22)]) == []


def test_empty_ports_no_findings() -> None:
    assert _f([]) == []


# ── base CVE embarquée (bannière / version) ──────────────────────────────────

def test_vsftpd_backdoor_cve_from_banner() -> None:
    findings = _f([PortLike(port=21, banner="220 (vsFTPd 2.3.4)")])
    cves = {f["cve_id"] for f in findings}
    assert "CVE-2011-2523" in cves
    # + la règle d'exposition FTP
    assert any(f["source"] == "rule" for f in findings)


def test_apache_2449_cve_from_version() -> None:
    findings = _f([PortLike(port=80, service_version="Apache/2.4.49 (Unix)")])
    crit = [f for f in findings if f["cve_id"] == "CVE-2021-41773"]
    assert crit and crit[0]["severity"] == "critical"


def test_cve_match_case_insensitive() -> None:
    findings = _f([PortLike(port=21, banner="VSFTPD 2.3.4")])
    assert any(f["cve_id"] == "CVE-2011-2523" for f in findings)


def test_findings_carry_port_number() -> None:
    findings = _f([PortLike(port=23)])
    assert findings[0]["port"] == 23


# ── risk_from_severities ──────────────────────────────────────────────────────

def test_risk_empty_is_safe() -> None:
    assert vuln.risk_from_severities([]) == "safe"


def test_risk_low_is_safe() -> None:
    assert vuln.risk_from_severities(["low", "info"]) == "safe"


def test_risk_medium_is_vulnerable() -> None:
    assert vuln.risk_from_severities(["medium"]) == "vulnerable"


def test_risk_high_is_vulnerable() -> None:
    assert vuln.risk_from_severities(["low", "high"]) == "vulnerable"


def test_risk_critical_wins() -> None:
    assert vuln.risk_from_severities(["medium", "critical", "low"]) == "critical"


# ── service_name_for ──────────────────────────────────────────────────────────

def test_service_name_from_port() -> None:
    assert vuln.service_name_for(22, None) == "ssh"


def test_service_name_prefers_provided() -> None:
    assert vuln.service_name_for(22, "custom-ssh") == "custom-ssh"


def test_service_name_unknown_port() -> None:
    assert vuln.service_name_for(49999, None) is None
