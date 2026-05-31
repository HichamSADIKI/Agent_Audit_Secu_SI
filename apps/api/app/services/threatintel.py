"""Renseignement de menace hors-ligne pour les flux sortants (Phase C).

Sans dépendance temps-réel : une liste noire embarquée (sous-ensemble
illustratif, à remplacer par un feed réel rafraîchi périodiquement) + des ports
connus pour le C2 / les portes dérobées. ``evaluate_flow`` renvoie une
(sévérité, raison) si le flux sortant est suspect, sinon ``None``.
"""
from __future__ import annotations

from app.models.network_event import SEVERITY_CRITICAL, SEVERITY_HIGH

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


def evaluate_flow(remote_ip: str, remote_port: int) -> tuple[str, str] | None:
    """Évalue un flux sortant. Retourne (severity, reason) si suspect."""
    if remote_ip in BLOCKLIST_IPS:
        return (SEVERITY_CRITICAL, "Connexion vers une IP en liste noire")
    label = SUSPICIOUS_PORTS.get(remote_port)
    if label is not None:
        return (SEVERITY_HIGH, f"Connexion sortante vers un port suspect ({label})")
    return None
