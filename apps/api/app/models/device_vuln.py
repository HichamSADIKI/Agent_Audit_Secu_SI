"""Modèle vulnérabilité — détectée sur un appareil par règles + base CVE offline (Phase B)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

# Sévérités (du plus faible au plus fort).
SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# Origine de la détection.
SOURCE_RULE = "rule"        # heuristique d'exposition (port sensible exposé…)
SOURCE_CVE_DB = "cve-db"    # base CVE hors-ligne embarquée (banner/version)


class DeviceVuln(Base):
    __tablename__ = "device_vulns"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    port_id: Mapped[int | None] = mapped_column(
        ForeignKey("device_ports.id", ondelete="CASCADE")
    )
    cve_id: Mapped[str | None] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    cvss: Mapped[float | None] = mapped_column(Float)
    description: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
