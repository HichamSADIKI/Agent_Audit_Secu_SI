"""Modèle événement réseau — intrusions & anomalies détectées (Phase C).

Couvre les heuristiques de diff de scan (nouvel appareil, nouveau port, ARP
spoofing) et l'analyse des flux sortants (IP/port suspects, scan de ports).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

# Types d'événement.
KIND_NEW_DEVICE = "new_device"
KIND_NEW_OPEN_PORT = "new_open_port"
KIND_PORT_SCAN = "port_scan"
KIND_ARP_SPOOF = "arp_spoof"
KIND_OUTBOUND_SUSPICIOUS = "outbound_suspicious"

# Sévérités (alignées sur device_vuln).
SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# Cycle de vie.
STATUS_OPEN = "open"
STATUS_ACK = "acknowledged"


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    machine_id: Mapped[int] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), index=True, nullable=False
    )
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(45))
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(16), default=STATUS_OPEN, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
