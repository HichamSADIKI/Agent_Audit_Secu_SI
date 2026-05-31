"""Service d'événements réseau (Phase C) : enregistrement + dédup + pub/sub WS."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import redis_client
from app.models.network_event import NetworkEvent
from app.services.alerting import REDIS_EVENTS_CHANNEL

log = logging.getLogger(__name__)


async def record_event(
    db: AsyncSession,
    *,
    machine_id: int,
    kind: str,
    severity: str,
    message: str,
    device_id: int | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    details: dict[str, Any] | None = None,
    dedup_window_minutes: int | None = None,
) -> bool:
    """Enregistre un événement réseau (ajouté à la transaction, pas de commit ici).

    Si ``dedup_window_minutes`` est fourni, n'insère pas si un événement de même
    (machine, kind, dst_ip, dst_port) existe déjà dans la fenêtre — évite de
    re-signaler la même chose à chaque scan. Retourne True si inséré.
    """
    if dedup_window_minutes is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=dedup_window_minutes)
        exists = await db.scalar(
            select(NetworkEvent.id).where(
                NetworkEvent.machine_id == machine_id,
                NetworkEvent.kind == kind,
                NetworkEvent.dst_ip.is_(dst_ip) if dst_ip is None else NetworkEvent.dst_ip == dst_ip,
                NetworkEvent.dst_port.is_(dst_port)
                if dst_port is None
                else NetworkEvent.dst_port == dst_port,
                NetworkEvent.created_at >= cutoff,
            )
        )
        if exists is not None:
            return False

    db.add(
        NetworkEvent(
            machine_id=machine_id,
            device_id=device_id,
            kind=kind,
            severity=severity,
            message=message,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            details=details,
        )
    )
    await _publish(
        {
            "event": "network.event",
            "kind": kind,
            "severity": severity,
            "machine_id": machine_id,
        }
    )
    return True


async def _publish(payload: dict) -> None:
    try:
        await redis_client.publish(REDIS_EVENTS_CHANNEL, json.dumps(payload))
    except Exception:  # noqa: BLE001
        log.warning("Redis publish failed — network event dropped: %s", payload)
