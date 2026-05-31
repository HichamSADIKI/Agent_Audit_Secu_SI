"""Modèle port — port ouvert découvert sur un appareil (Phase B)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class DevicePort(Base):
    __tablename__ = "device_ports"
    __table_args__ = (
        UniqueConstraint("device_id", "port", "protocol", name="uq_device_port_proto"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp", nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(64))
    service_version: Mapped[str | None] = mapped_column(String(128))
    banner: Mapped[str | None] = mapped_column(Text)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
