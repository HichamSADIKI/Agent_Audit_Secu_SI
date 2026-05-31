"""Tests du calcul de l'état réseau (fonction pure _build_reasons)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services import network


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _state(reasons) -> str:
    """Réplique la sélection de get_summary : état = raison la plus grave."""
    if not reasons:
        return "sain"
    return max(reasons, key=lambda r: network._STATE_RANK[r.state]).state


def _build(**over):
    base = dict(
        total=5,
        last_scan_at=_now(),
        now=_now(),
        down=0,
        down_gateways=0,
        new_last_window=0,
        crit_vuln_devices=0,
        high_vuln_devices=0,
        med_vuln_devices=0,
    )
    base.update(over)
    return network._build_reasons(**base)


# ── angle mort ────────────────────────────────────────────────────────────────

def test_no_devices_is_indisponible() -> None:
    assert _state(_build(total=0)) == "indisponible"


def test_stale_scan_is_indisponible() -> None:
    old = _now() - timedelta(hours=2)
    assert _state(_build(last_scan_at=old)) == "indisponible"


def test_no_scan_is_indisponible() -> None:
    assert _state(_build(last_scan_at=None)) == "indisponible"


# ── connectivité (Phase A) ────────────────────────────────────────────────────

def test_clean_network_is_sain() -> None:
    assert _state(_build()) == "sain"


def test_down_gateway_is_critique() -> None:
    assert _state(_build(down=1, down_gateways=1)) == "critique"


def test_down_host_is_alarme() -> None:
    assert _state(_build(down=2, down_gateways=0)) == "alarme"


def test_new_device_is_surveille() -> None:
    assert _state(_build(new_last_window=3)) == "surveille"


# ── vulnérabilités (Phase B) ──────────────────────────────────────────────────

def test_critical_vuln_is_critique() -> None:
    assert _state(_build(crit_vuln_devices=1)) == "critique"


def test_high_vuln_is_alarme() -> None:
    assert _state(_build(high_vuln_devices=2)) == "alarme"


def test_medium_vuln_is_surveille() -> None:
    assert _state(_build(med_vuln_devices=1)) == "surveille"


# ── intrusions & saturation (Phase C) ─────────────────────────────────────────

def test_arp_spoof_is_critique() -> None:
    assert _state(_build(arp_events=1)) == "critique"


def test_outbound_suspicious_is_critique() -> None:
    assert _state(_build(outbound_events=1)) == "critique"


def test_port_scan_is_alarme() -> None:
    assert _state(_build(portscan_events=1)) == "alarme"


def test_new_open_port_is_surveille() -> None:
    assert _state(_build(new_port_events=1)) == "surveille"


def test_saturated_is_sature() -> None:
    assert _state(_build(saturated=True, recent_new=12)) == "sature"


def test_most_severe_reason_wins() -> None:
    # saturation (sature) + vuln critique (critique) → critique l'emporte
    reasons = _build(saturated=True, recent_new=12, crit_vuln_devices=1)
    assert _state(reasons) == "critique"
