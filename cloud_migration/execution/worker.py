import argparse
import hashlib
import json
import logging
import os
import signal
import socket
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from database import SessionLocal

from ..execution_service import MUTATING_ACTIONS, _env_bool, _json_load
from ..models import (
    MigrationAuditEvent,
    MigrationEvidenceArtifact,
    MigrationExecutionJob,
    MigrationWorkerHeartbeat,
    MigrationWave,
)
from ..service import _client_id, _environment, validate_module_license
from .aws import AwsExecutionAdapter, AwsExecutionError
from .mock_aws import MockAwsExecutionAdapter
from .mode import MOCK_EXECUTION_MODE, validate_execution_mode


logger = logging.getLogger("cloud_migration.execution.worker")
STOP_REQUESTED = False


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def _worker_id() -> str:
    configured = os.getenv("CLOUD_MIGRATION_WORKER_ID", "").strip()
    return configured or f"{socket.gethostname()}-{os.getpid()}"


def record_heartbeat(db: Session, worker_id: str, mode: str) -> None:
    now = datetime.utcnow()
    client_id = _client_id()
    heartbeat = db.query(MigrationWorkerHeartbeat).filter_by(worker_id=worker_id).first()
    if not heartbeat:
        heartbeat = MigrationWorkerHeartbeat(
            worker_id=worker_id,
            client_id=client_id,
            execution_mode=mode,
            status="RUNNING",
            started_at=now,
            last_seen_at=now,
        )
        db.add(heartbeat)
    else:
        heartbeat.client_id = client_id
        heartbeat.execution_mode = mode
        heartbeat.status = "RUNNING"
        heartbeat.last_seen_at = now
    db.commit()


def _handle_signal(signum: int, _frame: Any) -> None:
    global STOP_REQUESTED
    logger.info("Worker shutdown requested by signal %s", signum)
    STOP_REQUESTED = True


def _canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)


def _evidence(
    db: Session,
    job: MigrationExecutionJob,
    outcome: str,
    payload: Dict[str, Any],
) -> MigrationEvidenceArtifact:
    envelope = {
        "schema_version": "v1alpha1",
        "job_id": job.id,
        "project_id": job.project_id,
        "wave_id": job.wave_id,
        "action": job.action,
        "outcome": outcome,
        "requested_by": job.requested_by,
        "approved_by": job.approved_by,
        "plan_version": job.plan_version,
        "recorded_at": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
        "payload": payload,
    }
    serialized = _canonical_json(envelope)
    artifact = MigrationEvidenceArtifact(
        id=str(uuid.uuid4()),
        client_id=job.client_id,
        project_id=job.project_id,
        wave_id=job.wave_id,
        job_id=job.id,
        evidence_type=f"{job.action.lower()}-{outcome.lower()}",
        content_sha256=hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        payload_json=serialized,
    )
    db.add(artifact)
    return artifact


def _audit(db: Session, job: MigrationExecutionJob, event_type: str, worker_id: str, payload: Dict[str, Any]) -> None:
    db.add(
        MigrationAuditEvent(
            id=str(uuid.uuid4()),
            client_id=job.client_id,
            actor=f"worker:{worker_id}"[:256],
            event_type=event_type,
            entity_type="execution-job",
            entity_id=job.id,
            payload_json=_canonical_json(payload),
        )
    )


def claim_next_job(db: Session, worker_id: str) -> Optional[MigrationExecutionJob]:
    now = datetime.utcnow()
    lease_seconds = _env_int("CLOUD_MIGRATION_WORKER_LEASE_SECONDS", 900, 60, 3600)

    expired = (
        db.query(MigrationExecutionJob)
        .filter(
            MigrationExecutionJob.status == "RUNNING",
            MigrationExecutionJob.lease_expires_at.isnot(None),
            MigrationExecutionJob.lease_expires_at < now,
        )
        .all()
    )
    for item in expired:
        item.status = "QUEUED" if item.attempts < item.max_attempts else "FAILED"
        item.error_code = "WORKER_LEASE_EXPIRED"
        item.error_message = "The previous worker lease expired before completion."
        item.lease_owner = None
        item.lease_expires_at = None
        item.not_before = now
        item.version += 1
        if item.status == "FAILED":
            item.completed_at = now
            _evidence(db, item, "FAILED", {"error_code": item.error_code, "error_message": item.error_message})
    if expired:
        db.commit()

    query = (
        db.query(MigrationExecutionJob)
        .filter(
            MigrationExecutionJob.status == "QUEUED",
            MigrationExecutionJob.not_before <= now,
        )
        .order_by(MigrationExecutionJob.created_at.asc())
    )
    if db.bind is not None and db.bind.dialect.name != "sqlite":
        query = query.with_for_update(skip_locked=True)
    job = query.first()
    if not job:
        db.rollback()
        return None
    job.status = "RUNNING"
    job.attempts += 1
    job.version += 1
    job.lease_owner = worker_id
    job.lease_expires_at = now + timedelta(seconds=lease_seconds)
    job.started_at = job.started_at or now
    job.error_code = None
    job.error_message = None
    _audit(db, job, "EXECUTION_JOB_STARTED", worker_id, {"action": job.action, "attempt": job.attempts})
    db.commit()
    db.refresh(job)
    return job


def _validate_job(db: Session, job: MigrationExecutionJob) -> tuple[MigrationWave, Any]:
    wave = (
        db.query(MigrationWave)
        .filter(MigrationWave.id == job.wave_id)
        .first()
    )
    if not wave or wave.project.client_id != job.client_id:
        raise RuntimeError("Execution job references a missing or cross-tenant wave.")
    environment = _environment(db, wave.project.target_environment)
    validate_module_license(
        target_environment=environment.name,
        aws_account_id=environment.aws_account_id,
    )
    if wave.plan_version != job.plan_version:
        raise RuntimeError(
            f"Execution job plan version {job.plan_version} is stale; current version is {wave.plan_version}."
    )
    if job.action in MUTATING_ACTIONS:
        if not wave.approved_by or not wave.plan_summary:
            raise RuntimeError("Mutating execution requires an approved wave plan.")
        if not job.approved_by:
            raise RuntimeError("Mutating execution requires a separately recorded approver.")
        if not _env_bool("CLOUD_MIGRATION_AWS_EXECUTION_ENABLED", False):
            raise RuntimeError("AWS migration execution is locked for this installation.")
        if job.action == "FINALIZE_CUTOVER" and not _env_bool("CLOUD_MIGRATION_FINALIZATION_ENABLED", False):
            raise RuntimeError("Cutover finalization has a separate installation safety lock.")
    return wave, environment


def _apply_reconciliation(wave: MigrationWave, result: Dict[str, Any]) -> None:
    servers = {str(item.get("source_ref") or "").lower(): item for item in result.get("servers") or []}
    observed_statuses = []
    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    for workload in wave.workloads:
        observed = servers.get(workload.source_ref.lower())
        if not observed:
            continue
        metadata = _json_load(workload.metadata_json)
        metadata["aws_mgn"] = {
            "source_server_id": observed.get("source_server_id"),
            "lifecycle_state": observed.get("lifecycle_state"),
            "replication_state": observed.get("replication_state"),
            "lag_duration": observed.get("lag_duration"),
            "last_snapshot_date_time": observed.get("last_snapshot_date_time"),
            "launched_ec2_instance_id": observed.get("launched_ec2_instance_id"),
            "is_archived": observed.get("is_archived"),
            "last_reconciled_at": timestamp,
        }
        workload.metadata_json = _canonical_json(metadata)
        workload.status = observed.get("workload_status") or "UNKNOWN"
        observed_statuses.append(workload.status)

    if not observed_statuses:
        return
    if wave.status == "FINALIZED" and all(
        item in {"CUTOVER_COMPLETE", "DISCONNECTED"} for item in observed_statuses
    ):
        return
    order = [
        "REPLICATION_BLOCKED",
        "AGENT_PENDING",
        "DISCOVERED",
        "REPLICATING",
        "TEST_READY",
        "TEST_IN_PROGRESS",
        "CUTOVER_READY",
        "CUTOVER_IN_PROGRESS",
        "CUTOVER_COMPLETE",
        "DISCONNECTED",
    ]
    rank = {value: index for index, value in enumerate(order)}
    wave.status = min(observed_statuses, key=lambda item: rank.get(item, -1))


def _enqueue_reconciliation(db: Session, job: MigrationExecutionJob) -> None:
    if job.action not in MUTATING_ACTIONS:
        return
    key = f"reconcile-after:{job.id}"
    if db.query(MigrationExecutionJob).filter_by(client_id=job.client_id, idempotency_key=key).first():
        return
    follow_up = MigrationExecutionJob(
        id=str(uuid.uuid4()),
        client_id=job.client_id,
        project_id=job.project_id,
        wave_id=job.wave_id,
        action="RECONCILE",
        provider=job.provider,
        status="QUEUED",
        idempotency_key=key,
        request_json="{}",
        requested_by=f"worker:{job.lease_owner or 'system'}"[:256],
        plan_version=job.plan_version,
        not_before=datetime.utcnow() + timedelta(seconds=15),
    )
    db.add(follow_up)


def execute_claimed_job(
    db: Session,
    job: MigrationExecutionJob,
    worker_id: str,
    adapter: Any,
) -> Dict[str, Any]:
    wave, environment = _validate_job(db, job)
    request = _json_load(job.request_json)
    if getattr(adapter, "mock", False):
        request["_mock_servers"] = []
        for workload in wave.workloads:
            metadata = _json_load(workload.metadata_json)
            observed = metadata.get("aws_mgn") or {}
            request["_mock_servers"].append({"source_ref": workload.source_ref, **observed})
    role_arn = environment.target_aws_role_arn or environment.client_aws_role_arn or ""
    result = adapter.execute(
        action=job.action,
        job_id=job.id,
        wave_id=job.wave_id,
        region=wave.target_region or environment.aws_region,
        expected_account_id=wave.project.target_account_id,
        role_arn=role_arn,
        source_refs=[item.source_ref for item in wave.workloads],
        request=request,
    )
    if job.action == "RECONCILE" or getattr(adapter, "mock", False):
        _apply_reconciliation(wave, result)
    if job.action == "FINALIZE_CUTOVER":
        wave.status = "FINALIZED"

    job.status = "SUCCEEDED"
    job.result_json = _canonical_json(result)
    job.error_code = None
    job.error_message = None
    job.completed_at = datetime.utcnow()
    job.lease_owner = None
    job.lease_expires_at = None
    job.version += 1
    _evidence(db, job, "SUCCEEDED", result)
    _audit(db, job, "EXECUTION_JOB_SUCCEEDED", worker_id, {"action": job.action})
    _enqueue_reconciliation(db, job)
    db.commit()
    return result


def fail_claimed_job(db: Session, job: MigrationExecutionJob, worker_id: str, exc: Exception) -> None:
    db.rollback()
    current = db.query(MigrationExecutionJob).filter_by(id=job.id).first()
    if not current:
        logger.error("Execution job %s disappeared while handling failure", job.id)
        return
    now = datetime.utcnow()
    retry = current.attempts < current.max_attempts and not isinstance(
        exc,
        (AwsExecutionError, HTTPException, RuntimeError, ValueError),
    )
    current.status = "QUEUED" if retry else "FAILED"
    current.error_code = exc.__class__.__name__[:128]
    current.error_message = str(exc)[:4000]
    current.lease_owner = None
    current.lease_expires_at = None
    current.version += 1
    if retry:
        current.not_before = now + timedelta(seconds=min(300, 30 * (2 ** max(0, current.attempts - 1))))
    else:
        current.completed_at = now
    outcome = "RETRYING" if retry else "FAILED"
    _evidence(
        db,
        current,
        outcome,
        {"error_code": current.error_code, "error_message": current.error_message, "attempt": current.attempts},
    )
    _audit(
        db,
        current,
        "EXECUTION_JOB_RETRY_SCHEDULED" if retry else "EXECUTION_JOB_FAILED",
        worker_id,
        {"action": current.action, "attempt": current.attempts, "error_code": current.error_code},
    )
    db.commit()


def run_once(worker_id: str, adapter: Any, mode: Optional[str] = None) -> bool:
    db = SessionLocal()
    try:
        record_heartbeat(
            db,
            worker_id,
            mode or (MOCK_EXECUTION_MODE if getattr(adapter, "mock", False) else "aws"),
        )
        job = claim_next_job(db, worker_id)
        if not job:
            return False
        logger.info("Claimed migration execution job %s action=%s attempt=%s", job.id, job.action, job.attempts)
        try:
            execute_claimed_job(db, job, worker_id, adapter)
            logger.info("Completed migration execution job %s", job.id)
        except Exception as exc:
            logger.exception("Migration execution job %s failed", job.id)
            fail_claimed_job(db, job, worker_id, exc)
        return True
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the client-hosted Cloud Migration Factory execution worker.")
    parser.add_argument("--once", action="store_true", help="Process at most one available job and exit.")
    arguments = parser.parse_args()
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    worker_id = _worker_id()
    mode = validate_execution_mode()
    adapter = MockAwsExecutionAdapter() if mode == MOCK_EXECUTION_MODE else AwsExecutionAdapter()
    polling_seconds = _env_int("CLOUD_MIGRATION_WORKER_POLL_SECONDS", 5, 1, 60)
    logger.info("Cloud Migration Factory worker started id=%s execution_mode=%s", worker_id, mode)
    if arguments.once:
        run_once(worker_id, adapter, mode)
        return
    while not STOP_REQUESTED:
        if not run_once(worker_id, adapter, mode):
            time.sleep(polling_seconds)
    logger.info("Cloud Migration Factory worker stopped id=%s", worker_id)


if __name__ == "__main__":
    main()
