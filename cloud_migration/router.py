from typing import Any, Callable

from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy.orm import Session

from .schemas import (
    ExecutionAction,
    MigrationExecutionJobApprovalRequest,
    MigrationExecutionJobRequest,
    MigrationProjectCreate,
    MigrationWaveApprovalRequest,
    MigrationWaveCreate,
    MigrationWavePlanRequest,
)
from .execution_service import (
    approve_execution_job,
    enqueue_execution_job,
    get_execution_evidence,
    get_execution_job,
    list_execution_jobs,
)
from .service import (
    adapter_capabilities,
    approve_wave,
    capabilities,
    create_project,
    create_wave,
    get_project,
    list_audit_events,
    list_projects,
    list_waves,
    migration_compatibility,
    plan_wave,
)


def build_cloud_migration_router(
    principal_dependency: Callable[..., Any],
    db_dependency: Callable[..., Any],
) -> APIRouter:
    router = APIRouter(prefix="/cloud-migration", tags=["Cloud Migration Factory"])

    @router.get("/capabilities")
    def get_capabilities(principal: Any = Depends(principal_dependency)):
        return capabilities()

    @router.get("/adapters")
    def get_adapters(principal: Any = Depends(principal_dependency)):
        return adapter_capabilities(principal)

    @router.get("/compatibility")
    def get_compatibility(
        source_type: str = Query(..., min_length=2, max_length=64),
        target_provider: str = Query(default="aws", min_length=2, max_length=32),
        strategy: str = Query(default="rehost", min_length=2, max_length=32),
        principal: Any = Depends(principal_dependency),
    ):
        return migration_compatibility(principal, source_type, target_provider, strategy)

    @router.get("/projects")
    def get_projects(
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return {"projects": list_projects(db, principal)}

    @router.post("/projects", status_code=201)
    def post_project(
        request: MigrationProjectCreate,
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return create_project(db, principal, request)

    @router.get("/projects/{project_id}")
    def get_project_by_id(
        project_id: str,
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return get_project(db, principal, project_id)

    @router.get("/projects/{project_id}/waves")
    def get_project_waves(
        project_id: str,
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return {"waves": list_waves(db, principal, project_id)}

    @router.post("/projects/{project_id}/waves", status_code=201)
    def post_project_wave(
        project_id: str,
        request: MigrationWaveCreate,
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return create_wave(db, principal, project_id, request)

    @router.post("/waves/{wave_id}/plan")
    def post_wave_plan(
        wave_id: str,
        request: MigrationWavePlanRequest,
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return plan_wave(db, principal, wave_id, request.expected_version)

    @router.post("/waves/{wave_id}/approve")
    def post_wave_approval(
        wave_id: str,
        request: MigrationWaveApprovalRequest,
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return approve_wave(db, principal, wave_id, request)

    @router.get("/waves/{wave_id}/jobs")
    def get_wave_execution_jobs(
        wave_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return {"jobs": list_execution_jobs(db, principal, wave_id, limit)}

    @router.post("/waves/{wave_id}/jobs/{action_name}", status_code=202)
    def post_wave_execution_job(
        wave_id: str,
        action_name: ExecutionAction,
        request: MigrationExecutionJobRequest,
        idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=8, max_length=128),
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return enqueue_execution_job(db, principal, wave_id, action_name, request, idempotency_key)

    @router.get("/jobs/{job_id}")
    def get_job_by_id(
        job_id: str,
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return get_execution_job(db, principal, job_id)

    @router.post("/jobs/{job_id}/approve", status_code=202)
    def post_job_approval(
        job_id: str,
        request: MigrationExecutionJobApprovalRequest,
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return approve_execution_job(db, principal, job_id, request)

    @router.get("/evidence/{evidence_id}")
    def get_evidence_by_id(
        evidence_id: str,
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return get_execution_evidence(db, principal, evidence_id)

    @router.get("/audit-events")
    def get_audit_events(
        limit: int = Query(default=100, ge=1, le=500),
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return {"events": list_audit_events(db, principal, limit)}

    return router
