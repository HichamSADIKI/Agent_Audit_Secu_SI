"""Rafraîchissement des feeds de menace réels (Phase C).

Best-effort : télécharge une blocklist d'IP (par défaut abuse.ch Feodo) via
``urllib`` (stdlib, exécuté dans un thread pour ne pas bloquer l'event loop) et
la stocke dans un set Redis consommé par ``threatintel.load_blocklist``. En cas
d'échec (hors-ligne, feed indisponible), la détection retombe sur la liste noire
embarquée — aucune erreur propagée.

Appelé périodiquement par le scheduler (instance unique).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import urllib.request

from app.core.config import settings
from app.core.redis import redis_client
from app.services.threatintel import BLOCKLIST_REDIS_KEY

log = logging.getLogger(__name__)


def _download(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "GuardianOps-AI"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 (URL de config)
        return resp.read().decode("utf-8", "replace")


def _parse_ips(text: str) -> set[str]:
    """Extrait les IP valides (ignore commentaires `#` et en-têtes ; gère CSV)."""
    ips: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(",")[0].strip()
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        ips.add(token)
    return ips


async def refresh_blocklist() -> int:
    """Télécharge la blocklist et la stocke dans Redis. Retourne le nb d'IP (0 si échec)."""
    if not settings.network_feeds_enabled:
        return 0
    try:
        text = await asyncio.to_thread(_download, settings.network_blocklist_feed_url)
    except Exception as exc:  # noqa: BLE001
        log.warning("Téléchargement blocklist échoué (%s) — repli embarqué conservé", exc)
        return 0

    ips = _parse_ips(text)
    if not ips:
        log.warning("Blocklist vide après parsing — Redis non modifié")
        return 0

    try:
        async with redis_client.pipeline(transaction=True) as pipe:
            pipe.delete(BLOCKLIST_REDIS_KEY)
            pipe.sadd(BLOCKLIST_REDIS_KEY, *ips)
            pipe.expire(BLOCKLIST_REDIS_KEY, settings.network_feed_ttl_hours * 3600)
            await pipe.execute()
    except Exception as exc:  # noqa: BLE001
        log.warning("Écriture blocklist Redis échouée (%s)", exc)
        return 0

    log.info("Blocklist rafraîchie : %d IP", len(ips))
    return len(ips)
