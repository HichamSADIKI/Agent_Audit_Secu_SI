"""Configuration centralisée, lue depuis les variables d'environnement."""
from __future__ import annotations

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Valeurs par défaut connues — refusées au démarrage.
_WEAK_SECRETS = frozenset(
    {
        "change-me-in-production",
        "change-me-in-production-please-use-a-long-random-string",
        "secret",
        "jwt_secret",
    }
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Application
    app_name: str = "GuardianOps AI"
    environment: str = "development"

    # Base de données
    database_url: str = "postgresql+psycopg://guardian:guardian@db:5432/guardianops"

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # Sécurité
    jwt_secret: str = "change-me-in-production"
    jwt_alg: str = "HS256"
    access_token_ttl_minutes: int = 30
    agent_token_ttl_days: int = 365

    # Alerting — seuils configurables (cf. PLAN.md §3)
    alert_cpu_threshold: float = 90.0
    alert_mem_threshold: float = 90.0
    alert_disk_threshold: float = 90.0
    alert_cpu_consecutive_points: int = 3
    alert_offline_minutes: int = 2

    # Détection d'anomalies (z-score robuste par machine, base médiane/MAD)
    anomaly_enabled: bool = True
    anomaly_window: int = 60            # taille de la fenêtre de référence (échantillons)
    anomaly_min_samples: int = 20       # minimum requis avant de détecter (démarrage à froid)
    anomaly_consecutive_points: int = 2  # nb de points anormaux consécutifs requis
    anomaly_z_threshold: float = 3.5    # seuil de z-score robuste (MAD)
    anomaly_abs_floor: float = 5.0      # écart absolu mini (points de %) si base ~constante

    # Scan réseau / état du réseau
    network_scan_stale_minutes: int = 15      # au-delà → état "indisponible" (angle mort)
    network_new_device_window_hours: int = 24  # fenêtre "nouvel appareil" pour l'état réseau

    # Intrusions / flux sortants (Phase C)
    network_event_window_minutes: int = 60       # fenêtre des événements influençant l'état
    network_event_dedup_minutes: int = 60        # anti-spam (même IP/port suspect)
    network_saturation_new_devices: int = 10     # nb de nouveaux appareils → état "saturé"
    network_saturation_window_minutes: int = 10  # fenêtre courte pour la saturation
    network_portscan_distinct_targets: int = 30  # fan-out de flux → scan de ports

    # Feeds de menace réels (blocklist IP) — rafraîchis par le scheduler
    network_feeds_enabled: bool = True
    network_blocklist_feed_url: str = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    network_feed_refresh_minutes: int = 60
    network_feed_ttl_hours: int = 48

    # CORS — liste séparée par des virgules
    cors_origins: str = "http://localhost:3300"

    @field_validator("jwt_secret")
    @classmethod
    def jwt_secret_must_be_strong(cls, v: str) -> str:
        if v in _WEAK_SECRETS or len(v) < 32:
            raise ValueError(
                "JWT_SECRET est trop faible ou utilise une valeur par défaut connue. "
                "Définissez une valeur aléatoire d'au moins 32 caractères dans .env.\n"
                "  python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
