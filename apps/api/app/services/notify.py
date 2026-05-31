"""Notifications sortantes (webhook) pour les signaux critiques (Phase C+).

Best-effort, sans dépendance runtime : POST JSON via ``urllib`` exécuté dans un
thread (n'interrompt jamais la requête en cours, n'échoue jamais bruyamment).
Compatible Slack / Mattermost (``text``), Discord (``content``) ou format
générique. Gating par seuil de sévérité configurable.
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.request

from app.core.config import settings

log = logging.getLogger(__name__)

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _payload(text: str, severity: str, title: str, message: str) -> dict:
    fmt = settings.notify_format
    if fmt == "discord":
        return {"content": text}
    if fmt == "generic":
        return {"text": text, "severity": severity, "title": title, "message": message}
    return {"text": text}  # slack / mattermost par défaut


def _post(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")  # noqa: S310 (URL de config)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


async def maybe_notify(*, severity: str, title: str, message: str) -> bool:
    """Envoie une notification si activé et si la sévérité atteint le seuil.

    Retourne True si une notification a été envoyée. Best-effort : toute erreur
    est loggée et avalée (ne propage jamais).
    """
    if not settings.notify_enabled or not settings.notify_webhook_url:
        return False
    threshold = _RANK.get(settings.notify_min_severity, _RANK["high"])
    if _RANK.get(severity, 0) < threshold:
        return False

    text = f"[GuardianOps][{severity.upper()}] {title} — {message}"
    try:
        await asyncio.to_thread(
            _post, settings.notify_webhook_url, _payload(text, severity, title, message)
        )
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("Notification webhook échouée (%s)", exc)
        return False
