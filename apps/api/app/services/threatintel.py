"""Renseignement de menace pour les flux sortants (Phase C).

Liste noire = repli embarqué **∪** feed réel rafraîchi par le scheduler dans
Redis (`services/feeds.py` : abuse.ch Feodo). ``load_blocklist`` charge l'union
en un appel Redis (à utiliser une fois par lot de flux). Plus des ports connus
pour le C2 / les portes dérobées. ``evaluate_flow`` (synchrone, embarqué seul)
reste disponible pour les tests / appels hors-ligne.
"""
from __future__ import annotations

import logging

from app.core.redis import redis_client
from app.models.network_event import SEVERITY_CRITICAL, SEVERITY_HIGH

log = logging.getLogger(__name__)

# Clé Redis alimentée par le scheduler (feed réel).
BLOCKLIST_REDIS_KEY = "guardianops:blocklist:ips"

# Liste noire d'IP (illustrative — remplacer par un feed type Feodo/abuse.ch).
BLOCKLIST_IPS: frozenset[str] = frozenset(
    {
        "185.220.101.1",   # nœud de sortie Tor (exemple)
        "45.137.21.9",     # C2 connu (exemple)
        "193.142.146.35",  # scanner/brute-force massif (exemple)
        "5.188.206.18",    # malware distribution (exemple)
        "198.51.100.66",   # réservé documentation — utilisé pour la démo
    }
)

# Ports fréquemment associés au C2 / aux portes dérobées (sortant).
SUSPICIOUS_PORTS: dict[int, str] = {
    4444: "Metasploit / Meterpreter",
    4445: "Metasploit",
    1337: "porte dérobée « leet »",
    31337: "Back Orifice",
    6667: "IRC (C2 botnet)",
    6697: "IRC/TLS (C2 botnet)",
    9001: "Tor (ORPort)",
    9030: "Tor (DirPort)",
    5555: "Android Debug Bridge (ADB)",
    2323: "Telnet alternatif (Mirai)",
}


async def load_blocklist() -> set[str]:
    """Union de la blocklist embarquée et du feed Redis (un seul appel Redis)."""
    ips = set(BLOCKLIST_IPS)
    try:
        members = await redis_client.smembers(BLOCKLIST_REDIS_KEY)
        ips.update(m.decode() if isinstance(m, bytes) else m for m in members)
    except Exception as exc:  # noqa: BLE001
        log.debug("Blocklist Redis indisponible (%s) — repli embarqué", exc)
    return ips


def suspicious_port(remote_port: int) -> tuple[str, str] | None:
    """(severity, reason) si le port distant est un port C2/backdoor connu."""
    label = SUSPICIOUS_PORTS.get(remote_port)
    if label is not None:
        return (SEVERITY_HIGH, f"Connexion sortante vers un port suspect ({label})")
    return None


def evaluate_flow(remote_ip: str, remote_port: int) -> tuple[str, str] | None:
    """Évalue un flux (synchrone, blocklist embarquée seule). Retourne (severity, reason)."""
    if remote_ip in BLOCKLIST_IPS:
        return (SEVERITY_CRITICAL, "Connexion vers une IP en liste noire")
    return suspicious_port(remote_port)
