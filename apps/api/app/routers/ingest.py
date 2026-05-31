"""Endpoints d'ingestion (authentification agent uniquement)."""
from __future__ import annotations

from fastapi import APIRouter, status

from app.deps import CurrentAgent, DbSession
from app.schemas.ingest import (
    HeartbeatResponse,
    IngestMetricsRequest,
    IngestMetricsResponse,
)
from app.schemas.network import FlowsRequest, FlowsResponse, ScanRequest, ScanResponse
from app.services import alerting, anomaly, network
from app.services.ingestion import ingest_metrics, record_heartbeat

router = APIRouter(prefix="/ingest", tags=["ingest"])


@router.post(
    "/metrics",
    response_model=IngestMetricsResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def post_metrics(
    payload: IngestMetricsRequest,
    db: DbSession,
    machine: CurrentAgent,
) -> IngestMetricsResponse:
    """Ingère un batch de métriques (vidange offline queue incluse)."""
    inserted = await ingest_metrics(db, machine, payload.samples)
    await alerting.check_threshold_alerts(db, machine)
    await anomaly.check_anomalies(db, machine)
    return IngestMetricsResponse(inserted=inserted)


@router.post(
    "/heartbeat",
    response_model=HeartbeatResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def post_heartbeat(db: DbSession, machine: CurrentAgent) -> HeartbeatResponse:
    """Met à jour last_seen_at et passe le statut machine à 'online'."""
    await record_heartbeat(db, machine)
    await alerting.resolve_offline_if_needed(db, machine)
    return HeartbeatResponse(status="ok")


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def post_scan(
    payload: ScanRequest,
    db: DbSession,
    machine: CurrentAgent,
) -> ScanResponse:
    """Ingère un snapshot de scan réseau (upsert des appareils découverts)."""
    return await network.ingest_scan(db, machine, payload)


@router.post(
    "/flows",
    response_model=FlowsResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def post_flows(
    payload: FlowsRequest,
    db: DbSession,
    machine: CurrentAgent,
) -> FlowsResponse:
    """Ingère les flux sortants observés et signale les intrusions (Phase C)."""
    return await network.ingest_flows(db, machine, payload.flows)
