"""Moteur de vulnérabilités hors-ligne (Phase B).

Deux sources, sans aucune dépendance réseau :
 1. **Règles d'exposition** — un service sensible exposé sur le réseau est un
    risque en soi (Telnet en clair, RDP/VNC ouverts, base de données exposée…).
 2. **Base CVE embarquée** — correspondance par sous-chaîne sur la bannière /
    version du service (sous-ensemble curé de CVE connues, à étendre).

`evaluate(ports)` renvoie une liste de findings (dicts) que le service réseau
persiste dans `device_vulns`.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.models.device_vuln import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SOURCE_CVE_DB,
    SOURCE_RULE,
)

# Ordre de gravité (pour comparer / agréger).
SEVERITY_RANK = {
    SEVERITY_INFO: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}


@dataclass
class PortLike:
    port: int
    service_name: str | None = None
    service_version: str | None = None
    banner: str | None = None


# Noms de service par port (best-effort si l'agent ne les renseigne pas).
PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 515: "printer", 587: "smtp", 631: "ipp", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 5901: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 9100: "jetdirect", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


def service_name_for(port: int, provided: str | None) -> str | None:
    return provided or PORT_SERVICES.get(port)


# ── Règles d'exposition (port → finding) ─────────────────────────────────────
# (title, severity, cvss, description)
_EXPOSURE_RULES: dict[int, tuple[str, str, float | None, str]] = {
    23: ("Telnet en clair exposé", SEVERITY_HIGH, 7.5,
         "Le protocole Telnet transmet identifiants et données sans chiffrement."),
    21: ("FTP non chiffré exposé", SEVERITY_MEDIUM, 5.3,
         "FTP transmet les identifiants en clair ; préférer SFTP/FTPS."),
    3389: ("RDP exposé sur le réseau", SEVERITY_HIGH, 7.5,
           "Le Bureau à distance Windows est une cible fréquente de force brute / RCE."),
    5900: ("VNC exposé sur le réseau", SEVERITY_HIGH, 7.5,
           "VNC est souvent mal authentifié et exposé sans tunnel."),
    5901: ("VNC exposé sur le réseau", SEVERITY_HIGH, 7.5,
           "VNC est souvent mal authentifié et exposé sans tunnel."),
    445: ("SMB exposé sur le réseau", SEVERITY_MEDIUM, 6.5,
          "Le partage de fichiers SMB exposé augmente la surface d'attaque (ex. EternalBlue)."),
    161: ("SNMP exposé", SEVERITY_MEDIUM, 5.3,
          "SNMP (communautés par défaut public/private) expose des informations système."),
    3306: ("Base MySQL exposée", SEVERITY_HIGH, 7.5,
           "Un SGBD ne devrait pas être joignable directement depuis le réseau."),
    5432: ("Base PostgreSQL exposée", SEVERITY_HIGH, 7.5,
           "Un SGBD ne devrait pas être joignable directement depuis le réseau."),
    1433: ("Base MSSQL exposée", SEVERITY_HIGH, 7.5,
           "Un SGBD ne devrait pas être joignable directement depuis le réseau."),
    27017: ("Base MongoDB exposée", SEVERITY_HIGH, 7.5,
            "MongoDB exposé sans authentification a causé de nombreuses fuites."),
    6379: ("Redis exposé sans authentification", SEVERITY_CRITICAL, 9.8,
           "Redis exposé est souvent non authentifié → exécution de commandes / RCE."),
    9200: ("Elasticsearch exposé", SEVERITY_HIGH, 7.5,
           "Elasticsearch exposé sans contrôle d'accès expose toutes les données indexées."),
    11211: ("Memcached exposé", SEVERITY_HIGH, 7.5,
            "Memcached exposé permet fuite de données et amplification DDoS."),
    80: ("Service HTTP non chiffré", SEVERITY_LOW, 3.1,
         "Le trafic HTTP n'est pas chiffré ; préférer HTTPS."),
    9100: ("Port d'impression brut exposé (JetDirect)", SEVERITY_LOW, 3.1,
           "Le port 9100 permet d'envoyer des travaux d'impression sans authentification."),
}


# ── Base CVE embarquée (sous-chaîne bannière/version → CVE) ───────────────────
# (needle, cve_id, title, severity, cvss, description). Sous-ensemble illustratif.
_CVE_DB: list[tuple[str, str, str, str, float, str]] = [
    ("vsftpd 2.3.4", "CVE-2011-2523", "vsftpd 2.3.4 — backdoor", SEVERITY_CRITICAL, 9.8,
     "La version 2.3.4 de vsftpd contient une porte dérobée donnant un shell root."),
    ("proftpd 1.3.5", "CVE-2015-3306", "ProFTPD 1.3.5 — mod_copy RCE", SEVERITY_CRITICAL, 9.8,
     "mod_copy permet la copie de fichiers arbitraires et l'exécution de code."),
    ("apache/2.4.49", "CVE-2021-41773", "Apache httpd 2.4.49 — path traversal/RCE", SEVERITY_CRITICAL, 9.8,
     "Traversée de chemin pouvant mener à l'exécution de code à distance."),
    ("apache/2.4.50", "CVE-2021-42013", "Apache httpd 2.4.50 — path traversal/RCE", SEVERITY_CRITICAL, 9.8,
     "Contournement du correctif de CVE-2021-41773."),
    ("openssh_7.2", "CVE-2016-6210", "OpenSSH < 7.3 — énumération d'utilisateurs", SEVERITY_MEDIUM, 5.3,
     "Différence de temps de réponse permettant d'énumérer les comptes valides."),
    ("openssh_7.", "CVE-2018-15473", "OpenSSH < 7.8 — énumération d'utilisateurs", SEVERITY_MEDIUM, 5.3,
     "Réponse différenciée permettant d'énumérer les utilisateurs valides."),
    ("microsoft-iis/6.0", "CVE-2017-7269", "IIS 6.0 — WebDAV buffer overflow (RCE)", SEVERITY_HIGH, 8.1,
     "Débordement de tampon dans ScStoragePathFromUrl (WebDAV) → exécution de code."),
    ("openssl/1.0.1", "CVE-2014-0160", "OpenSSL 1.0.1 — Heartbleed", SEVERITY_HIGH, 7.5,
     "Fuite de mémoire du serveur via l'extension TLS Heartbeat."),
    ("exim 4.8", "CVE-2019-10149", "Exim < 4.92 — RCE (The Return of the WIZard)", SEVERITY_CRITICAL, 9.8,
     "Exécution de commandes via une adresse destinataire forgée."),
    ("samba", "CVE-2017-7494", "Samba — SambaCry RCE", SEVERITY_CRITICAL, 9.8,
     "Chargement d'une bibliothèque partagée arbitraire via un partage inscriptible (versions < 4.6.4)."),
]


def evaluate(ports: list[PortLike]) -> list[dict]:
    """Retourne les findings de vulnérabilité pour les ports d'un appareil."""
    findings: list[dict] = []
    for p in ports:
        # 1) règles d'exposition
        rule = _EXPOSURE_RULES.get(p.port)
        if rule is not None:
            title, severity, cvss, desc = rule
            findings.append(
                {
                    "port": p.port,
                    "cve_id": None,
                    "title": title,
                    "severity": severity,
                    "cvss": cvss,
                    "description": desc,
                    "source": SOURCE_RULE,
                }
            )

        # 2) base CVE embarquée (bannière + version, insensible à la casse)
        haystack = " ".join(
            filter(None, [p.banner or "", p.service_version or ""])
        ).lower()
        if haystack.strip():
            for needle, cve_id, title, severity, cvss, desc in _CVE_DB:
                if needle in haystack:
                    findings.append(
                        {
                            "port": p.port,
                            "cve_id": cve_id,
                            "title": title,
                            "severity": severity,
                            "cvss": cvss,
                            "description": desc,
                            "source": SOURCE_CVE_DB,
                        }
                    )
    return findings


def risk_from_severities(severities: list[str]) -> str:
    """Niveau de risque appareil agrégé : critical / vulnerable / safe."""
    if not severities:
        return "safe"
    top = max(SEVERITY_RANK.get(s, 0) for s in severities)
    if top >= SEVERITY_RANK[SEVERITY_CRITICAL]:
        return "critical"
    if top >= SEVERITY_RANK[SEVERITY_MEDIUM]:
        return "vulnerable"
    return "safe"
