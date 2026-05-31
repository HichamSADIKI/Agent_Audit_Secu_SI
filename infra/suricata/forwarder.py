#!/usr/bin/env python3
"""Forwarder Suricata → GuardianOps (Phase C, sidecar IDS).

Tail `eve.json`, filtre les lignes `event_type == "alert"`, et les POST à
`/ingest/ids`. S'enrôle comme un agent (token d'enrôlement → agent JWT persisté).
Stdlib uniquement (pas de dépendance), pensé pour une image python-slim légère.

Variables d'environnement :
  API_URL            URL de l'API (défaut http://api:8000)
  IDS_ENROLL_TOKEN   token d'enrôlement (créé via POST /machines) — requis au 1er run
  EVE_PATH           chemin d'eve.json (défaut /var/log/suricata/eve.json)
  STATE_PATH         fichier d'état (agent_token) (défaut /state/state.json)
  FORWARDER_HOSTNAME nom d'hôte déclaré (défaut suricata-ids)
  BATCH_MAX          nb max d'alertes par envoi (défaut 100)
  POLL_SECS          intervalle de lecture (défaut 2)
"""
from __future__ import annotations

import json
import os
import time
import urllib.request

API_URL = os.environ.get("API_URL", "http://api:8000").rstrip("/")
ENROLL_TOKEN = os.environ.get("IDS_ENROLL_TOKEN", "")
EVE_PATH = os.environ.get("EVE_PATH", "/var/log/suricata/eve.json")
STATE_PATH = os.environ.get("STATE_PATH", "/state/state.json")
HOSTNAME = os.environ.get("FORWARDER_HOSTNAME", "suricata-ids")
BATCH_MAX = int(os.environ.get("BATCH_MAX", "100"))
POLL_SECS = float(os.environ.get("POLL_SECS", "2"))


def _post(path: str, body: dict, token: str | None = None) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(f"{API_URL}{path}", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode() or "{}")


def _load_token() -> str | None:
    try:
        with open(STATE_PATH) as f:
            return json.load(f).get("agent_token")
    except (OSError, ValueError):
        return None


def _save_token(token: str) -> None:
    os.makedirs(os.path.dirname(STATE_PATH) or ".", exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump({"agent_token": token}, f)


def _enroll() -> str:
    if not ENROLL_TOKEN:
        raise SystemExit("IDS_ENROLL_TOKEN requis au premier lancement (POST /machines).")
    resp = _post(
        "/agents/enroll",
        {"enroll_token": ENROLL_TOKEN, "hostname": HOSTNAME, "os": "suricata"},
    )
    token = resp["agent_token"]
    _save_token(token)
    print(f"[forwarder] enrôlé : machine_id={resp.get('machine_id')}", flush=True)
    return token


def _to_alert(evt: dict) -> dict | None:
    if evt.get("event_type") != "alert":
        return None
    a = evt.get("alert", {})
    sig = a.get("signature")
    if not sig:
        return None
    return {
        "signature": sig[:512],
        "category": (a.get("category") or None),
        "severity": int(a.get("severity", 3)),
        "src_ip": evt.get("src_ip"),
        "dest_ip": evt.get("dest_ip"),
        "dest_port": evt.get("dest_port"),
        "proto": evt.get("proto"),
    }


def _flush(batch: list[dict], token: str) -> None:
    if not batch:
        return
    try:
        resp = _post("/ingest/ids", {"alerts": batch}, token=token)
        print(f"[forwarder] {len(batch)} alerte(s) → recorded={resp.get('recorded')}", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[forwarder] envoi échoué : {exc}", flush=True)


def main() -> None:
    token = _load_token() or _enroll()
    print(f"[forwarder] surveillance de {EVE_PATH} → {API_URL}/ingest/ids", flush=True)

    # Attendre l'apparition du fichier (Suricata peut démarrer après.)
    while not os.path.exists(EVE_PATH):
        time.sleep(POLL_SECS)

    f = open(EVE_PATH)
    f.seek(0, os.SEEK_END)  # ne pas rejouer l'historique
    inode = os.fstat(f.fileno()).st_ino

    while True:
        line = f.readline()
        if not line:
            # Gérer la rotation de log (inode changé / fichier tronqué).
            try:
                if os.stat(EVE_PATH).st_ino != inode:
                    f.close()
                    f = open(EVE_PATH)
                    inode = os.fstat(f.fileno()).st_ino
                    continue
            except OSError:
                pass
            time.sleep(POLL_SECS)
            continue

        batch: list[dict] = []
        while line and len(batch) < BATCH_MAX:
            try:
                alert = _to_alert(json.loads(line))
                if alert:
                    batch.append(alert)
            except ValueError:
                pass
            line = f.readline()
        _flush(batch, token)


if __name__ == "__main__":
    main()
