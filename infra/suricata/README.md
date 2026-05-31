# Sidecar IDS Suricata (Phase C)

Inspection de trafic par signatures, **optionnelle** et découplée du cœur :
Suricata sniffe une interface et écrit `eve.json` ; un petit forwarder pousse les
alertes (`event_type: alert`) à l'API (`POST /ingest/ids`), qui les enregistre
comme événements réseau `ids_alert` (visibles dans la page **Intrusions**).

```
trafic ──▶ Suricata ──(eve.json, volume)──▶ forwarder ──HTTP──▶ /ingest/ids ──▶ network_events
```

## Mise en route

1. **Créer une machine IDS** et récupérer son token d'enrôlement :
   ```bash
   curl -s -X POST http://localhost:8800/machines \
     -H "Authorization: Bearer <JWT_USER>" -H "Content-Type: application/json" \
     -d '{"name":"suricata-ids"}'
   # → noter "enroll_token"
   ```
2. **Configurer `.env`** :
   ```
   IDS_ENROLL_TOKEN=<enroll_token>
   SURICATA_IFACE=eth0          # interface à écouter
   IDS_API_URL=http://api:8000  # API interne (défaut)
   ```
3. **Lancer** :
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.suricata.yml up -d suricata ids-forwarder
   ```

## Notes

- Suricata nécessite `NET_ADMIN`/`NET_RAW` + **réseau hôte** pour capturer le
  trafic (Linux). Sur un switch, brancher l'interface sur un **port miroir (SPAN)**.
- Mettre à jour les règles dans le conteneur Suricata : `suricata-update`.
- Le forwarder ne rejoue pas l'historique (il se positionne en fin de fichier) et
  gère la rotation de log. Token agent persisté dans le volume `/state`.
- Le mapping de priorité Suricata → sévérité GuardianOps : 1 → high, 2 → medium,
  ≥3 → low (`app/services/network.py::_ids_severity`).
