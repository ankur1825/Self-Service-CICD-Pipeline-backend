from typing import Any, Callable

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .schemas import (
    MigrationProjectCreate,
    MigrationWaveApprovalRequest,
    MigrationWaveCreate,
    MigrationWavePlanRequest,
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

    @router.get("/audit-events")
    def get_audit_events(
        limit: int = Query(default=100, ge=1, le=500),
        db: Session = Depends(db_dependency),
        principal: Any = Depends(principal_dependency),
    ):
        return {"events": list_audit_events(db, principal, limit)}

    return router
