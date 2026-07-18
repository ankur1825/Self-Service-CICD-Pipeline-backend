import json
import os
import uuid
from typing import Any, Dict, Iterable, List, Optional

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from enterprise.licensing import (
    LicenseValidationError,
    default_license_from_env,
    license_summary,
    validate_license,
)
from models import EnvironmentCatalog

from .adapters import adapter_registry
from .models import MigrationAuditEvent, MigrationProject, MigrationWave, MigrationWorkload
from .providers.aws import AwsMigrationAdapter
from .schemas import MigrationProjectCreate, MigrationWaveApprovalRequest, MigrationWaveCreate


PIPELINE_NAME = "Cloud Migration Factory"
REQUIRED_ENTITLEMENTS = ["cloud_migration", "cloud_migration_aws"]

ROLE_PLATFORM_ADMIN = "platform-admin"
ROLE_MIGRATION_ARCHITECT = "migration-architect"
ROLE_MIGRATION_OPERATOR = "migration-operator"
ROLE_MIGRATION_APPROVER = "migration-approver"
ROLE_MIGRATION_AUDITOR = "migration-auditor"

READ_ROLES = {
    ROLE_PLATFORM_ADMIN,
    ROLE_MIGRATION_ARCHITECT,
    ROLE_MIGRATION_OPERATOR,
    ROLE_MIGRATION_APPROVER,
    ROLE_MIGRATION_AUDITOR,
}
AUTHOR_ROLES = {ROLE_PLATFORM_ADMIN, ROLE_MIGRATION_ARCHITECT, ROLE_MIGRATION_OPERATOR}
APPROVER_ROLES = {ROLE_PLATFORM_ADMIN, ROLE_MIGRATION_APPROVER}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _principal_name(principal: Any) -> str:
    return str(getattr(principal, "email", "") or getattr(principal, "username", "") or "unknown")


def _principal_roles(principal: Any) -> set[str]:
    return {str(role).strip().lower() for role in (getattr(principal, "roles", None) or []) if str(role).strip()}


def require_migration_role(principal: Any, allowed_roles: set[str], action: str) -> None:
    if not _principal_roles(principal).intersection(allowed_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{action} requires one of these roles: {', '.join(sorted(allowed_roles))}.",
        )


def principal_can_use_environment(principal: Any, environment: str) -> bool:
    roles = _principal_roles(principal)
    if ROLE_PLATFORM_ADMIN in roles:
        return True
    return bool(roles.intersection(READ_ROLES - {ROLE_MIGRATION_AUDITOR}))


def _license_document() -> Dict[str, Any]:
    return default_license_from_env()


def _client_id() -> str:
    client_id = str(_license_document().get("client_id") or "").strip()
    if not client_id:
        raise HTTPException(status_code=403, detail="The installed license does not identify a client tenant.")
    return client_id


def _validation_environment(license_doc: Dict[str, Any]) -> str:
    allowed = license_doc.get("allowed_environments") or []
    return str(allowed[0] if allowed else "DEV")


def validate_module_license(
    *,
    target_environment: Optional[str] = None,
    aws_account_id: Optional[str] = None,
    required_entitlements: Optional[List[str]] = None,
) -> Dict[str, Any]:
    if not _env_bool("CLOUD_MIGRATION_ENABLED", True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cloud Migration Factory is disabled for this installation.")
    if not _env_bool("CLOUD_MIGRATION_AWS_ENABLED", True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="The AWS migration provider is disabled for this installation.")
    license_doc = _license_document()
    try:
        return validate_license(
            license_doc,
            pipeline_name=PIPELINE_NAME,
            target_env=target_environment or _validation_environment(license_doc),
            requested_features=required_entitlements or REQUIRED_ENTITLEMENTS,
            aws_account_id=aws_account_id,
        )
    except LicenseValidationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


def capabilities() -> Dict[str, Any]:
    adapter = AwsMigrationAdapter()
    provider = adapter.capabilities()
    provider["source_types"] = [
        item.key for item in adapter_registry.capabilities("source")
    ]
    provider["migration_methods"] = [
        {
            "key": item.key,
            "display_name": item.display_name,
            "status": item.status,
            "recommended": item.recommended,
            "license_mode": item.license_mode,
        }
        for item in adapter_registry.capabilities("transfer")
        if "aws" in item.target_providers
    ]
    license_doc = _license_document()
    licensed = _env_bool("CLOUD_MIGRATION_ENABLED", True)
    reason = None if licensed else "Cloud Migration Factory is disabled for this installation."
    validated = license_doc
    if licensed:
        try:
            validated = validate_license(
                license_doc,
                pipeline_name=PIPELINE_NAME,
                target_env=_validation_environment(license_doc),
                requested_features=REQUIRED_ENTITLEMENTS,
            )
        except LicenseValidationError as exc:
            licensed = False
            reason = str(exc)
    summary = license_summary(validated)
    summary.pop("license_key", None)

    return {
        "module": "cloud-migration",
        "display_name": PIPELINE_NAME,
        "licensed": licensed,
        "license_reason": reason,
        "license": summary,
        "required_entitlements": REQUIRED_ENTITLEMENTS,
        "providers": [provider],
        "adapter_catalog": adapter_registry.catalog(),
        "data_boundary": provider["data_boundary"],
    }


def adapter_capabilities(principal: Any) -> Dict[str, Any]:
    require_migration_role(principal, READ_ROLES, "Viewing migration adapters")
    validate_module_license()
    return adapter_registry.catalog()


def migration_compatibility(
    principal: Any,
    source_type: str,
    target_provider: str,
    strategy: str = "rehost",
) -> Dict[str, Any]:
    require_migration_role(principal, READ_ROLES, "Evaluating migration compatibility")
    validate_module_license()
    result = adapter_registry.compatibility(source_type, target_provider, strategy)
    for adapter in result["transfer_adapters"]:
        if adapter["status"] != "available":
            continue
        try:
            validate_module_license(required_entitlements=adapter["required_entitlements"])
        except HTTPException as exc:
            adapter["status"] = "unlicensed"
            adapter["unavailable_reason"] = str(exc.detail)

    available = [adapter for adapter in result["transfer_adapters"] if adapter["status"] == "available"]
    result["supported"] = bool(result["source_adapter"] and result["target_adapter"] and available)
    result["recommended_transfer_adapter"] = next(
        (adapter["key"] for adapter in available if adapter["recommended"]),
        available[0]["key"] if available else None,
    )
    if result["source_adapter"] and result["target_adapter"] and not available:
        result["reasons"].append("No licensed and configured transfer adapter is available for this path.")
    return result


def _environment(db: Session, name: str) -> EnvironmentCatalog:
    normalized = str(name or "").strip().upper()
    environment = db.query(EnvironmentCatalog).filter(EnvironmentCatalog.name == normalized).first()
    if not environment or not environment.is_active:
        raise HTTPException(status_code=404, detail=f"Active target environment '{normalized}' was not found.")
    if not environment.aws_account_id:
        raise HTTPException(status_code=400, detail=f"Environment '{normalized}' has no AWS account configured.")
    if not environment.aws_region:
        raise HTTPException(status_code=400, detail=f"Environment '{normalized}' has no AWS Region configured.")
    return environment


def _project(db: Session, project_id: str, client_id: str) -> MigrationProject:
    project = db.query(MigrationProject).filter_by(id=project_id, client_id=client_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Migration project was not found.")
    return project


def _wave(db: Session, wave_id: str, client_id: str) -> MigrationWave:
    wave = (
        db.query(MigrationWave)
        .join(MigrationProject)
        .filter(MigrationWave.id == wave_id, MigrationProject.client_id == client_id)
        .first()
    )
    if not wave:
        raise HTTPException(status_code=404, detail="Migration wave was not found.")
    return wave


def _audit(
    db: Session,
    *,
    client_id: str,
    principal: Any,
    event_type: str,
    entity_type: str,
    entity_id: str,
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    db.add(
        MigrationAuditEvent(
            id=str(uuid.uuid4()),
            client_id=client_id,
            actor=_principal_name(principal),
            event_type=event_type,
            entity_type=entity_type,
            entity_id=entity_id,
            payload_json=json.dumps(payload or {}, sort_keys=True),
        )
    )


def _workload_dict(workload: MigrationWorkload) -> Dict[str, Any]:
    return {
        "id": workload.id,
        "source_ref": workload.source_ref,
        "hostname": workload.hostname,
        "os_family": workload.os_family,
        "source_instance_type": workload.source_instance_type,
        "target_instance_type": workload.target_instance_type,
        "status": workload.status,
        "metadata": json.loads(workload.metadata_json) if workload.metadata_json else {},
        "created_at": workload.created_at,
        "updated_at": workload.updated_at,
    }


def wave_dict(wave: MigrationWave, include_plan: bool = True) -> Dict[str, Any]:
    result = {
        "id": wave.id,
        "project_id": wave.project_id,
        "name": wave.name,
        "migration_method": wave.migration_method,
        "migration_strategy": wave.migration_strategy,
        "transfer_profile_id": wave.transfer_profile_id,
        "source_region": wave.source_region,
        "target_region": wave.target_region,
        "maintenance_window": wave.maintenance_window,
        "status": wave.status,
        "plan_version": wave.plan_version,
        "requested_by": wave.requested_by,
        "approved_by": wave.approved_by,
        "approval_comment": wave.approval_comment,
        "workloads": [_workload_dict(item) for item in wave.workloads],
        "created_at": wave.created_at,
        "updated_at": wave.updated_at,
    }
    if include_plan:
        result["plan"] = json.loads(wave.plan_summary) if wave.plan_summary else None
    return result


def project_dict(project: MigrationProject, include_waves: bool = False) -> Dict[str, Any]:
    result = {
        "id": project.id,
        "client_id": project.client_id,
        "name": project.name,
        "description": project.description,
        "source_type": project.source_type,
        "target_provider": project.target_provider,
        "target_environment": project.target_environment,
        "target_account_id": project.target_account_id,
        "source_endpoint_id": project.source_endpoint_id,
        "target_endpoint_id": project.target_endpoint_id,
        "status": project.status,
        "created_by": project.created_by,
        "created_at": project.created_at,
        "updated_at": project.updated_at,
    }
    if include_waves:
        result["waves"] = [wave_dict(wave) for wave in project.waves]
    return result


def list_projects(db: Session, principal: Any) -> List[Dict[str, Any]]:
    require_migration_role(principal, READ_ROLES, "Viewing Cloud Migration Factory")
    validate_module_license()
    projects = (
        db.query(MigrationProject)
        .filter(MigrationProject.client_id == _client_id())
        .order_by(MigrationProject.updated_at.desc())
        .all()
    )
    for project in projects:
        validate_module_license(
            target_environment=project.target_environment,
            aws_account_id=project.target_account_id,
        )
    return [project_dict(project) for project in projects]


def get_project(db: Session, principal: Any, project_id: str) -> Dict[str, Any]:
    require_migration_role(principal, READ_ROLES, "Viewing a migration project")
    project = _project(db, project_id, _client_id())
    validate_module_license(
        target_environment=project.target_environment,
        aws_account_id=project.target_account_id,
    )
    return project_dict(project, include_waves=True)


def create_project(db: Session, principal: Any, request: MigrationProjectCreate) -> Dict[str, Any]:
    require_migration_role(principal, AUTHOR_ROLES, "Creating a migration project")
    project_name = request.name.strip()
    if not project_name:
        raise HTTPException(status_code=422, detail="Project name cannot be blank.")
    environment = _environment(db, request.target_environment)
    if not principal_can_use_environment(principal, environment.name):
        raise HTTPException(status_code=403, detail=f"Current roles cannot use environment '{environment.name}'.")
    license_doc = validate_module_license(
        target_environment=environment.name,
        aws_account_id=environment.aws_account_id,
    )
    client_id = str(license_doc.get("client_id") or _client_id())
    project = MigrationProject(
        id=str(uuid.uuid4()),
        client_id=client_id,
        name=project_name,
        description=request.description,
        source_type=request.source_type,
        target_provider=request.target_provider,
        target_environment=environment.name,
        target_account_id=environment.aws_account_id,
        created_by=_principal_name(principal),
    )
    db.add(project)
    _audit(
        db,
        client_id=client_id,
        principal=principal,
        event_type="PROJECT_CREATED",
        entity_type="project",
        entity_id=project.id,
        payload={"target_environment": environment.name, "target_provider": request.target_provider},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A migration project with this name already exists.") from exc
    db.refresh(project)
    return project_dict(project, include_waves=True)


def list_waves(db: Session, principal: Any, project_id: str) -> List[Dict[str, Any]]:
    require_migration_role(principal, READ_ROLES, "Viewing migration waves")
    project = _project(db, project_id, _client_id())
    validate_module_license(
        target_environment=project.target_environment,
        aws_account_id=project.target_account_id,
    )
    return [wave_dict(wave) for wave in project.waves]


def create_wave(
    db: Session,
    principal: Any,
    project_id: str,
    request: MigrationWaveCreate,
) -> Dict[str, Any]:
    require_migration_role(principal, AUTHOR_ROLES, "Creating a migration wave")
    wave_name = request.name.strip()
    if not wave_name:
        raise HTTPException(status_code=422, detail="Wave name cannot be blank.")
    if any(not item.source_ref.strip() for item in request.workloads):
        raise HTTPException(status_code=422, detail="Workload source references cannot be blank.")
    client_id = _client_id()
    project = _project(db, project_id, client_id)
    environment = _environment(db, project.target_environment)
    if not principal_can_use_environment(principal, environment.name):
        raise HTTPException(status_code=403, detail=f"Current roles cannot use environment '{environment.name}'.")
    validate_module_license(target_environment=environment.name, aws_account_id=environment.aws_account_id)

    compatibility = adapter_registry.compatibility(
        project.source_type,
        project.target_provider,
        "rehost",
    )
    selected_adapter = next(
        (
            adapter
            for adapter in compatibility["transfer_adapters"]
            if adapter["key"] == request.migration_method
        ),
        None,
    )
    if not selected_adapter:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Transfer method '{request.migration_method}' is not compatible with "
                f"source '{project.source_type}' and target '{project.target_provider}'."
            ),
        )
    if selected_adapter["status"] != "available":
        raise HTTPException(
            status_code=409,
            detail=selected_adapter.get("unavailable_reason") or "The selected transfer adapter is unavailable.",
        )
    validate_module_license(
        target_environment=environment.name,
        aws_account_id=environment.aws_account_id,
        required_entitlements=selected_adapter["required_entitlements"],
    )

    wave = MigrationWave(
        id=str(uuid.uuid4()),
        project_id=project.id,
        name=wave_name,
        migration_method=request.migration_method,
        source_region=(request.source_region or "").strip() or None,
        target_region=(request.target_region or environment.aws_region).strip(),
        maintenance_window=request.maintenance_window,
        requested_by=_principal_name(principal),
    )
    for item in request.workloads:
        wave.workloads.append(
            MigrationWorkload(
                id=str(uuid.uuid4()),
                source_ref=item.source_ref.strip(),
                hostname=item.hostname,
                os_family=item.os_family,
                source_instance_type=item.source_instance_type,
                target_instance_type=item.target_instance_type,
            )
        )
    db.add(wave)
    _audit(
        db,
        client_id=client_id,
        principal=principal,
        event_type="WAVE_CREATED",
        entity_type="wave",
        entity_id=wave.id,
        payload={"project_id": project.id, "workload_count": len(wave.workloads)},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Wave name or workload source references must be unique.") from exc
    db.refresh(wave)
    return wave_dict(wave)


def plan_wave(
    db: Session,
    principal: Any,
    wave_id: str,
    expected_version: Optional[int],
) -> Dict[str, Any]:
    require_migration_role(principal, AUTHOR_ROLES, "Planning a migration wave")
    client_id = _client_id()
    wave = _wave(db, wave_id, client_id)
    if expected_version is not None and expected_version != wave.plan_version:
        raise HTTPException(status_code=409, detail=f"Wave plan version changed; current version is {wave.plan_version}.")
    environment = _environment(db, wave.project.target_environment)
    validate_module_license(target_environment=environment.name, aws_account_id=environment.aws_account_id)
    plan = AwsMigrationAdapter().build_plan(wave.project, wave, wave.workloads, environment)
    wave.plan_version += 1
    plan["plan_version"] = wave.plan_version
    wave.plan_summary = json.dumps(plan, sort_keys=True)
    wave.status = "PLANNED" if not plan["blocking_issue_count"] else "DRAFT"
    wave.approved_by = None
    wave.approval_comment = None
    _audit(
        db,
        client_id=client_id,
        principal=principal,
        event_type="WAVE_PLANNED",
        entity_type="wave",
        entity_id=wave.id,
        payload={"plan_version": wave.plan_version, "blocking_issue_count": plan["blocking_issue_count"]},
    )
    db.commit()
    db.refresh(wave)
    return wave_dict(wave)


def approve_wave(
    db: Session,
    principal: Any,
    wave_id: str,
    request: MigrationWaveApprovalRequest,
) -> Dict[str, Any]:
    require_migration_role(principal, APPROVER_ROLES, "Approving a migration wave")
    client_id = _client_id()
    wave = _wave(db, wave_id, client_id)
    if wave.status != "PLANNED" or not wave.plan_summary:
        raise HTTPException(status_code=409, detail="Only a non-blocked PLANNED wave can be approved.")
    if request.expected_version is not None and request.expected_version != wave.plan_version:
        raise HTTPException(status_code=409, detail=f"Wave plan version changed; current version is {wave.plan_version}.")
    actor = _principal_name(principal)
    allow_self_approval = os.getenv("CLOUD_MIGRATION_ALLOW_SELF_APPROVAL", "false").lower() == "true"
    if not allow_self_approval and actor.lower() == wave.requested_by.lower():
        raise HTTPException(status_code=409, detail="Separation of duties prevents the wave requester from approving it.")
    environment = _environment(db, wave.project.target_environment)
    validate_module_license(target_environment=environment.name, aws_account_id=environment.aws_account_id)
    wave.status = "APPROVED"
    wave.approved_by = actor
    wave.approval_comment = request.comment
    _audit(
        db,
        client_id=client_id,
        principal=principal,
        event_type="WAVE_APPROVED",
        entity_type="wave",
        entity_id=wave.id,
        payload={"plan_version": wave.plan_version, "comment": request.comment},
    )
    db.commit()
    db.refresh(wave)
    return wave_dict(wave)


def list_audit_events(db: Session, principal: Any, limit: int = 100) -> List[Dict[str, Any]]:
    require_migration_role(principal, READ_ROLES, "Viewing migration audit history")
    validate_module_license()
    events: Iterable[MigrationAuditEvent] = (
        db.query(MigrationAuditEvent)
        .filter(MigrationAuditEvent.client_id == _client_id())
        .order_by(MigrationAuditEvent.created_at.desc())
        .limit(min(max(limit, 1), 500))
        .all()
    )
    return [
        {
            "id": event.id,
            "actor": event.actor,
            "event_type": event.event_type,
            "entity_type": event.entity_type,
            "entity_id": event.entity_id,
            "payload": json.loads(event.payload_json) if event.payload_json else {},
            "created_at": event.created_at,
        }
        for event in events
    ]
