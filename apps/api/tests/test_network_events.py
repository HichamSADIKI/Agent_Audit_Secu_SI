"""Tests des heuristiques d'intrusion (ingest_flows, ARP spoof) — DB mockée."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.models.machine import Machine
from app.models.network_event import (
    KIND_ARP_SPOOF,
    KIND_IDS_ALERT,
    KIND_OUTBOUND_SUSPICIOUS,
    KIND_PORT_SCAN,
)
from app.schemas.network import Flow, IdsAlert, ScanDevice
from app.services import network


def _machine(id_: int = 1) -> Machine:
    m = Machine(name="agent-host", status="online")
    m.id = id_
    return m


def _kinds(rec: AsyncMock) -> list[str]:
    return [c.kwargs["kind"] for c in rec.await_args_list]


# ── ingest_flows ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_blocklist_and_suspicious_port_flagged() -> None:
    db = AsyncMock()
    db.commit = AsyncMock()
    flows = [
        Flow(remote_ip="198.51.100.66", remote_port=443),   # blocklist → critical
        Flow(remote_ip="8.8.8.8", remote_port=4444),        # port C2 → high
        Flow(remote_ip="8.8.8.8", remote_port=443),         # bénin → ignoré
    ]
    with patch.object(network.events, "record_event", new=AsyncMock(return_value=True)) as rec:
        resp = await network.ingest_flows(db, _machine(), flows)

    kinds = _kinds(rec)
    assert kinds.count(KIND_OUTBOUND_SUSPICIOUS) == 2
    assert resp.received == 3
    assert resp.flagged == 2
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_port_scan_fanout_flagged() -> None:
    from app.core.config import settings

    db = AsyncMock()
    db.commit = AsyncMock()
    n = settings.network_portscan_distinct_targets
    flows = [Flow(remote_ip=f"203.0.113.{i}", remote_port=23) for i in range(1, n + 5)]

    with patch.object(network.events, "record_event", new=AsyncMock(return_value=True)) as rec:
        await network.ingest_flows(db, _machine(), flows)

    assert KIND_PORT_SCAN in _kinds(rec)


@pytest.mark.asyncio
async def test_no_flows_no_events() -> None:
    db = AsyncMock()
    db.commit = AsyncMock()
    with patch.object(network.events, "record_event", new=AsyncMock(return_value=True)) as rec:
        resp = await network.ingest_flows(db, _machine(), [])
    rec.assert_not_awaited()
    assert resp.flagged == 0


# ── détection ARP spoofing ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_arp_spoof_detected_for_shared_mac() -> None:
    db = AsyncMock()
    devices = [
        ScanDevice(ip="10.0.0.30", mac="DE:AD:BE:EF:00:30"),
        ScanDevice(ip="10.0.0.31", mac="DE:AD:BE:EF:00:30"),  # même MAC, autre IP
    ]
    with patch.object(network.events, "record_event", new=AsyncMock(return_value=True)) as rec:
        await network._detect_arp_spoof(db, 1, devices)

    assert _kinds(rec) == [KIND_ARP_SPOOF]


@pytest.mark.asyncio
async def test_no_arp_spoof_for_unique_macs() -> None:
    db = AsyncMock()
    devices = [
        ScanDevice(ip="10.0.0.30", mac="DE:AD:BE:EF:00:30"),
        ScanDevice(ip="10.0.0.31", mac="DE:AD:BE:EF:00:31"),
    ]
    with patch.object(network.events, "record_event", new=AsyncMock(return_value=True)) as rec:
        await network._detect_arp_spoof(db, 1, devices)
    rec.assert_not_awaited()


# ── alertes IDS (Suricata) ────────────────────────────────────────────────────

def test_ids_severity_mapping() -> None:
    assert network._ids_severity(1) == "high"
    assert network._ids_severity(2) == "medium"
    assert network._ids_severity(3) == "low"
    assert network._ids_severity(5) == "low"


@pytest.mark.asyncio
async def test_ingest_ids_alerts_records_events() -> None:
    db = AsyncMock()
    db.commit = AsyncMock()
    alerts = [
        IdsAlert(signature="ET MALWARE Win32/Agent", severity=1,
                 src_ip="10.0.0.5", dest_ip="8.8.8.8", dest_port=443, proto="TCP"),
        IdsAlert(signature="ET SCAN Nmap", severity=2),
    ]
    with patch.object(network.events, "record_event", new=AsyncMock(return_value=True)) as rec:
        resp = await network.ingest_ids_alerts(db, _machine(), alerts)

    assert _kinds(rec) == [KIND_IDS_ALERT, KIND_IDS_ALERT]
    assert resp.received == 2 and resp.recorded == 2
    db.commit.assert_awaited_once()
