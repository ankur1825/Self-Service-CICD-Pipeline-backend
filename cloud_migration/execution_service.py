import json
import hashlib
import os
import re
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import MigrationEvidenceArtifact, MigrationExecutionJob, MigrationWorkerHeartbeat
from .execution.mode import MOCK_EXECUTION_MODE, execution_mode, mock_execution_enabled
from .schemas import MigrationExecutionJobApprovalRequest, MigrationExecutionJobRequest
from .service import (
    APPROVER_ROLES,
    AUTHOR_ROLES,
    READ_ROLES,
    _audit,
    _client_id,
    _environment,
    _principal_name,
    _wave,
    require_migration_role,
    validate_module_license,
)


ACTION_MAP = {
    "preflight": "PREFLIGHT",
    "reconcile": "RECONCILE",
    "start-test": "START_TEST",
    "finalize-test": "FINALIZE_TEST",
    "start-cutover": "START_CUTOVER",
    "rollback": "ROLLBACK",
    "finalize-cutover": "FINALIZE_CUTOVER",
}
READ_ONLY_ACTIONS = {"PREFLIGHT", "RECONCILE"}
MUTATING_ACTIONS = set(ACTION_MAP.values()) - READ_ONLY_ACTIONS
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def _json_load(value: str | None) -> Dict[str, Any]:
    if not value:
        return {}
    try:
        result = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return result if isinstance(result, dict) else {}


def _evidence_summary(item: MigrationEvidenceArtifact) -> Dict[str, Any]:
    return {
        "id": item.id,
        "evidence_type": item.evidence_type,
        "content_sha256": item.content_sha256,
        "created_at": item.created_at,
    }


def job_dict(job: MigrationExecutionJob, evidence: Iterable[MigrationEvidenceArtifact] = ()) -> Dict[str, Any]:
    return {
        "id": job.id,
        "client_id": job.client_id,
        "project_id": job.project_id,
        "wave_id": job.wave_id,
        "action": job.action,
        "provider": job.provider,
        "status": job.status,
        "idempotency_key": job.idempotency_key,
        "request": _json_load(job.request_json),
        "result": _json_load(job.result_json) if job.result_json else None,
        "requested_by": job.requested_by,
        "approved_by": job.approved_by,
        "approval_comment": job.approval_comment,
        "plan_version": job.plan_version,
        "version": job.version,
        "attempts": job.attempts,
        "max_attempts": job.max_attempts,
        "error_code": job.error_code,
        "error_message": job.error_message,
        "not_before": job.not_before,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "evidence": [_evidence_summary(item) for item in evidence],
    }


def _job(db: Session, job_id: str, client_id: str) -> MigrationExecutionJob:
    job = db.query(MigrationExecutionJob).filter_by(id=job_id, client_id=client_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Migration execution job was not found.")
    return job


def _job_with_evidence(db: Session, job: MigrationExecutionJob) -> Dict[str, Any]:
    evidence = (
        db.query(MigrationEvidenceArtifact)
        .filter(MigrationEvidenceArtifact.job_id == job.id)
        .order_by(MigrationEvidenceArtifact.created_at.asc())
        .all()
    )
    return job_dict(job, evidence)


def _validate_action_gate(db: Session, job: MigrationExecutionJob) -> None:
    wave = _wave(db, job.wave_id, job.client_id)
    environment = _environment(db, wave.project.target_environment)
    validate_module_license(
        target_environment=environment.name,
        aws_account_id=environment.aws_account_id,
    )
    if job.action in MUTATING_ACTIONS:
        if not wave.approved_by or not wave.plan_summary:
            raise HTTPException(status_code=409, detail="Mutating execution requires an approved wave plan.")
        if wave.plan_version != job.plan_version:
            raise HTTPException(
                status_code=409,
                detail=f"The approved plan changed; current plan version is {wave.plan_version}.",
            )
        if not _env_bool("CLOUD_MIGRATION_AWS_EXECUTION_ENABLED", False):
            raise HTTPException(status_code=409, detail="AWS migration execution is locked for this installation.")
        if execution_mode() == MOCK_EXECUTION_MODE and not mock_execution_enabled():
            raise HTTPException(
                status_code=409,
                detail="Mock execution is selected but its separate installation safety lock is closed.",
            )
        if job.action == "FINALIZE_CUTOVER" and not _env_bool("CLOUD_MIGRATION_FINALIZATION_ENABLED", False):
            raise HTTPException(status_code=409, detail="Cutover finalization has a separate installation safety lock.")


def enqueue_execution_job(
    db: Session,
    principal: Any,
    wave_id: str,
    action_name: str,
    request: MigrationExecutionJobRequest,
    idempotency_key: str,
) -> Dict[str, Any]:
    require_migration_role(principal, AUTHOR_ROLES, "Requesting migration execution")
    action = ACTION_MAP.get(action_name)
    if not action:
        raise HTTPException(status_code=404, detail="Migration execution action was not found.")
    key = str(idempotency_key or "").strip()
    if not IDEMPOTENCY_KEY.fullmatch(key):
        raise HTTPException(
            status_code=422,
            detail="Idempotency-Key must be 8-128 characters using letters, digits, dot, underscore, colon, or hyphen.",
        )

    client_id = _client_id()
    wave = _wave(db, wave_id, client_id)
    if wave.migration_method != "mgn" or wave.project.target_provider != "aws":
        raise HTTPException(status_code=409, detail="The AWS execution worker currently supports AWS MGN waves only.")
    environment = _environment(db, wave.project.target_environment)
    validate_module_license(
        target_environment=environment.name,
        aws_account_id=environment.aws_account_id,
    )

    payload = request.model_dump()
    serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    existing = (
        db.query(MigrationExecutionJob)
        .filter_by(client_id=client_id, idempotency_key=key)
        .first()
    )
    if existing:
        if existing.wave_id != wave.id or existing.action != action or (existing.request_json or "{}") != serialized:
            raise HTTPException(status_code=409, detail="Idempotency-Key is already associated with a different request.")
        return _job_with_evidence(db, existing)

    active_statuses = ["AWAITING_APPROVAL", "QUEUED", "RUNNING"]
    active_count = (
        db.query(MigrationExecutionJob)
        .filter(
            MigrationExecutionJob.client_id == client_id,
            MigrationExecutionJob.status.in_(active_statuses),
        )
        .count()
    )
    max_active = _env_int("CLOUD_MIGRATION_MAX_ACTIVE_JOBS", 100, 1, 10000)
    if active_count >= max_active:
        raise HTTPException(
            status_code=429,
            detail=f"The tenant already has the configured maximum of {max_active} active execution jobs.",
        )
    if action in MUTATING_ACTIONS:
        active_mutation = (
            db.query(MigrationExecutionJob)
            .filter(
                MigrationExecutionJob.client_id == client_id,
                MigrationExecutionJob.wave_id == wave.id,
                MigrationExecutionJob.action.in_(MUTATING_ACTIONS),
                MigrationExecutionJob.status.in_(active_statuses),
            )
            .order_by(MigrationExecutionJob.created_at.asc())
            .first()
        )
        if active_mutation:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Wave mutation {active_mutation.action} is already {active_mutation.status}. "
                    "Complete it before requesting another lifecycle change."
                ),
            )

    job = MigrationExecutionJob(
        id=str(uuid.uuid4()),
        client_id=client_id,
        project_id=wave.project_id,
        wave_id=wave.id,
        action=action,
        provider="aws",
        status="QUEUED" if action in READ_ONLY_ACTIONS else "AWAITING_APPROVAL",
        idempotency_key=key,
        request_json=serialized,
        requested_by=_principal_name(principal),
        plan_version=wave.plan_version,
        not_before=datetime.utcnow(),
    )
    if action in MUTATING_ACTIONS:
        _validate_action_gate(db, job)
    db.add(job)
    _audit(
        db,
        client_id=client_id,
        principal=principal,
        event_type="EXECUTION_JOB_REQUESTED",
        entity_type="execution-job",
        entity_id=job.id,
        payload={"wave_id": wave.id, "action": action, "status": job.status},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="An execution request with this idempotency key already exists.") from exc
    db.refresh(job)
    return _job_with_evidence(db, job)


def list_execution_jobs(db: Session, principal: Any, wave_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    require_migration_role(principal, READ_ROLES, "Viewing migration execution jobs")
    client_id = _client_id()
    _wave(db, wave_id, client_id)
    validate_module_license()
    jobs = (
        db.query(MigrationExecutionJob)
        .filter_by(client_id=client_id, wave_id=wave_id)
        .order_by(MigrationExecutionJob.created_at.desc())
        .limit(min(max(limit, 1), 500))
        .all()
    )
    return [_job_with_evidence(db, item) for item in jobs]


def get_execution_job(db: Session, principal: Any, job_id: str) -> Dict[str, Any]:
    require_migration_role(principal, READ_ROLES, "Viewing a migration execution job")
    validate_module_license()
    return _job_with_evidence(db, _job(db, job_id, _client_id()))


def execution_health(db: Session, principal: Any) -> Dict[str, Any]:
    require_migration_role(principal, READ_ROLES, "Viewing migration worker health")
    validate_module_license()
    client_id = _client_id()
    jobs = db.query(MigrationExecutionJob).filter_by(client_id=client_id).all()
    counts: Dict[str, int] = {}
    for job in jobs:
        counts[job.status] = counts.get(job.status, 0) + 1
    now = datetime.utcnow()
    expired_leases = sum(
        1
        for job in jobs
        if job.status == "RUNNING" and job.lease_expires_at and job.lease_expires_at < now
    )
    queued = [job for job in jobs if job.status == "QUEUED"]
    oldest_queued_at = min((job.created_at for job in queued), default=None)
    configured = _env_bool("CLOUD_MIGRATION_WORKER_ENABLED", False)
    mode = execution_mode()
    mock_unlocked = mock_execution_enabled()
    heartbeat_timeout = _env_int("CLOUD_MIGRATION_WORKER_HEARTBEAT_TIMEOUT_SECONDS", 30, 5, 3600)
    heartbeat_cutoff = now.timestamp() - heartbeat_timeout
    heartbeats = (
        db.query(MigrationWorkerHeartbeat)
        .filter_by(client_id=client_id)
        .order_by(MigrationWorkerHeartbeat.last_seen_at.desc())
        .all()
    )
    live_workers = [item for item in heartbeats if item.last_seen_at.timestamp() >= heartbeat_cutoff]
    healthy = (
        configured
        and bool(live_workers)
        and expired_leases == 0
        and (mode != MOCK_EXECUTION_MODE or mock_unlocked)
    )
    return {
        "status": "healthy" if healthy else "attention",
        "worker_configured": configured,
        "execution_mode": mode,
        "mock_execution_enabled": mock_unlocked,
        "execution_enabled": _env_bool("CLOUD_MIGRATION_AWS_EXECUTION_ENABLED", False),
        "finalization_enabled": _env_bool("CLOUD_MIGRATION_FINALIZATION_ENABLED", False),
        "counts": counts,
        "active_job_count": sum(counts.get(item, 0) for item in ("AWAITING_APPROVAL", "QUEUED", "RUNNING")),
        "expired_lease_count": expired_leases,
        "live_worker_count": len(live_workers),
        "last_heartbeat_at": heartbeats[0].last_seen_at if heartbeats else None,
        "heartbeat_timeout_seconds": heartbeat_timeout,
        "oldest_queued_at": oldest_queued_at,
        "checked_at": now,
    }


def get_execution_evidence(db: Session, principal: Any, evidence_id: str) -> Dict[str, Any]:
    require_migration_role(principal, READ_ROLES, "Viewing migration execution evidence")
    validate_module_license()
    item = (
        db.query(MigrationEvidenceArtifact)
        .filter_by(id=evidence_id, client_id=_client_id())
        .first()
    )
    if not item:
        raise HTTPException(status_code=404, detail="Migration evidence artifact was not found.")
    actual_digest = hashlib.sha256(item.payload_json.encode("utf-8")).hexdigest()
    try:
        payload = json.loads(item.payload_json)
        parse_error = None
    except (TypeError, ValueError):
        payload = None
        parse_error = "Evidence payload is not valid JSON."
    return {
        **_evidence_summary(item),
        "project_id": item.project_id,
        "wave_id": item.wave_id,
        "job_id": item.job_id,
        "integrity_verified": actual_digest == item.content_sha256 and parse_error is None,
        "parse_error": parse_error,
        "payload": payload,
    }


def approve_execution_job(
    db: Session,
    principal: Any,
    job_id: str,
    request: MigrationExecutionJobApprovalRequest,
) -> Dict[str, Any]:
    require_migration_role(principal, APPROVER_ROLES, "Approving migration execution")
    client_id = _client_id()
    job = _job(db, job_id, client_id)
    if job.status != "AWAITING_APPROVAL":
        raise HTTPException(status_code=409, detail="Only an AWAITING_APPROVAL execution job can be approved.")
    if request.expected_version != job.version:
        raise HTTPException(status_code=409, detail=f"Execution job version changed; current version is {job.version}.")
    actor = _principal_name(principal)
    if actor.lower() == job.requested_by.lower():
        raise HTTPException(status_code=409, detail="Separation of duties prevents the requester from approving execution.")
    expected_confirmation = f"{job.action} {job.wave_id}"
    if request.confirmation.strip() != expected_confirmation:
        raise HTTPException(status_code=422, detail=f"Confirmation must exactly match: {expected_confirmation}")
    _validate_action_gate(db, job)

    job.status = "QUEUED"
    job.approved_by = actor
    job.approval_comment = request.comment
    job.version += 1
    job.not_before = datetime.utcnow()
    _audit(
        db,
        client_id=client_id,
        principal=principal,
        event_type="EXECUTION_JOB_APPROVED",
        entity_type="execution-job",
        entity_id=job.id,
        payload={"wave_id": job.wave_id, "action": job.action, "plan_version": job.plan_version},
    )
    db.commit()
    db.refresh(job)
    return _job_with_evidence(db, job)
