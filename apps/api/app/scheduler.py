"""Planificateur autonome de GuardianOps AI.

Process séparé de l'API (à exécuter en **instance unique**), ce qui permet de
mettre l'API à l'échelle horizontalement (plusieurs workers/répliques) sans
dupliquer la détection des machines offline.

Lancer avec :  python -m app.scheduler

Note : l'ouverture d'alerte est de toute façon idempotente au niveau base
(index unique partiel `uq_alerts_open_per_machine_type`), donc un doublon
accidentel de scheduler ne crée pas de doublon d'alerte — mais un seul suffit.
"""
from __future__ import annotations

import asyncio
import logging

from app.core.config import settings
from app.core.db import SessionLocal, engine
from app.core.redis import redis_client
from app.services import alerting, feeds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("guardianops.scheduler")

# Intervalle entre deux passes de vérification (secondes).
CHECK_INTERVAL_S = 30


async def _run() -> None:
    log.info(
        "Scheduler démarré — intervalle=%ss, seuil offline=%s min",
        CHECK_INTERVAL_S,
        settings.alert_offline_minutes,
    )
    # Rafraîchissement des feeds de menace toutes les N itérations (best-effort).
    feed_every = max(1, settings.network_feed_refresh_minutes * 60 // CHECK_INTERVAL_S)
    iteration = 0
    try:
        while True:
            try:
                async with SessionLocal() as db:
                    await alerting.check_offline_machines(db)
            except Exception:  # noqa: BLE001
                log.exception("Erreur lors de la vérification offline")

            if settings.network_feeds_enabled and iteration % feed_every == 0:
                try:
                    await feeds.refresh_blocklist()
                except Exception:  # noqa: BLE001
                    log.exception("Erreur lors du rafraîchissement des feeds")

            iteration += 1
            await asyncio.sleep(CHECK_INTERVAL_S)
    finally:
        await engine.dispose()
        await redis_client.aclose()


def main() -> None:
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        log.info("Scheduler arrêté")


if __name__ == "__main__":
    main()
