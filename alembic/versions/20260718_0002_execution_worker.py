"""Add durable execution jobs and evidence artifacts.

Revision ID: 20260718_0002
Revises: 20260718_0001
Create Date: 2026-07-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260718_0002"
down_revision: Union[str, Sequence[str], None] = "20260718_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())

    # Older installations created these tables through SQLAlchemy at API start,
    # before Alembic became the release gate. Bootstrap them here so a brand-new
    # PostgreSQL installation can run migrations before starting the API.
    if "cloud_migration_projects" not in tables:
        op.create_table(
            "cloud_migration_projects",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("client_id", sa.String(length=128), nullable=False),
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("source_type", sa.String(length=32), nullable=False),
            sa.Column("target_provider", sa.String(length=16), nullable=False, server_default="aws"),
            sa.Column("target_environment", sa.String(length=64), nullable=False),
            sa.Column("target_account_id", sa.String(length=64), nullable=False),
            sa.Column("source_endpoint_id", sa.String(length=36), nullable=True),
            sa.Column("target_endpoint_id", sa.String(length=36), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
            sa.Column("created_by", sa.String(length=256), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(
                ["source_endpoint_id"],
                ["cloud_migration_endpoints.id"],
                name="fk_cloud_migration_projects_source_endpoint_id",
            ),
            sa.ForeignKeyConstraint(
                ["target_endpoint_id"],
                ["cloud_migration_endpoints.id"],
                name="fk_cloud_migration_projects_target_endpoint_id",
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("client_id", "name", name="uq_cloud_migration_project_client_name"),
        )
        for column in ("client_id", "source_endpoint_id", "target_endpoint_id", "status"):
            op.create_index(f"ix_cloud_migration_projects_{column}", "cloud_migration_projects", [column])

    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "cloud_migration_waves" not in tables:
        op.create_table(
            "cloud_migration_waves",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("project_id", sa.String(length=36), nullable=False),
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("migration_method", sa.String(length=32), nullable=False, server_default="mgn"),
            sa.Column("migration_strategy", sa.String(length=32), nullable=False, server_default="rehost"),
            sa.Column("transfer_profile_id", sa.String(length=36), nullable=True),
            sa.Column("source_region", sa.String(length=64), nullable=True),
            sa.Column("target_region", sa.String(length=64), nullable=False),
            sa.Column("maintenance_window", sa.String(length=160), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
            sa.Column("plan_version", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("plan_summary", sa.Text(), nullable=True),
            sa.Column("requested_by", sa.String(length=256), nullable=False),
            sa.Column("approved_by", sa.String(length=256), nullable=True),
            sa.Column("approval_comment", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["project_id"], ["cloud_migration_projects.id"]),
            sa.ForeignKeyConstraint(
                ["transfer_profile_id"],
                ["cloud_migration_transfer_profiles.id"],
                name="fk_cloud_migration_waves_transfer_profile_id",
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("project_id", "name", name="uq_cloud_migration_wave_project_name"),
        )
        for column in ("project_id", "transfer_profile_id", "status"):
            op.create_index(f"ix_cloud_migration_waves_{column}", "cloud_migration_waves", [column])

    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "cloud_migration_workloads" not in tables:
        op.create_table(
            "cloud_migration_workloads",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("wave_id", sa.String(length=36), nullable=False),
            sa.Column("source_ref", sa.String(length=256), nullable=False),
            sa.Column("hostname", sa.String(length=256), nullable=True),
            sa.Column("os_family", sa.String(length=32), nullable=True),
            sa.Column("source_instance_type", sa.String(length=64), nullable=True),
            sa.Column("target_instance_type", sa.String(length=64), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="DISCOVERED"),
            sa.Column("metadata_json", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["wave_id"], ["cloud_migration_waves.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("wave_id", "source_ref", name="uq_cloud_migration_workload_wave_source"),
        )
        op.create_index("ix_cloud_migration_workloads_wave_id", "cloud_migration_workloads", ["wave_id"])
        op.create_index("ix_cloud_migration_workloads_status", "cloud_migration_workloads", ["status"])

    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "cloud_migration_audit_events" not in tables:
        op.create_table(
            "cloud_migration_audit_events",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("client_id", sa.String(length=128), nullable=False),
            sa.Column("actor", sa.String(length=256), nullable=False),
            sa.Column("event_type", sa.String(length=96), nullable=False),
            sa.Column("entity_type", sa.String(length=64), nullable=False),
            sa.Column("entity_id", sa.String(length=36), nullable=False),
            sa.Column("payload_json", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        for column in ("client_id", "event_type", "entity_id", "created_at"):
            op.create_index(f"ix_cloud_migration_audit_events_{column}", "cloud_migration_audit_events", [column])

    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "cloud_migration_execution_jobs" not in tables:
        op.create_table(
            "cloud_migration_execution_jobs",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("client_id", sa.String(length=128), nullable=False),
            sa.Column("project_id", sa.String(length=36), nullable=False),
            sa.Column("wave_id", sa.String(length=36), nullable=False),
            sa.Column("action", sa.String(length=32), nullable=False),
            sa.Column("provider", sa.String(length=16), nullable=False, server_default="aws"),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="QUEUED"),
            sa.Column("idempotency_key", sa.String(length=128), nullable=False),
            sa.Column("request_json", sa.Text(), nullable=True),
            sa.Column("result_json", sa.Text(), nullable=True),
            sa.Column("requested_by", sa.String(length=256), nullable=False),
            sa.Column("approved_by", sa.String(length=256), nullable=True),
            sa.Column("approval_comment", sa.Text(), nullable=True),
            sa.Column("plan_version", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
            sa.Column("error_code", sa.String(length=128), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("not_before", sa.DateTime(), nullable=False),
            sa.Column("lease_owner", sa.String(length=256), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(), nullable=True),
            sa.Column("started_at", sa.DateTime(), nullable=True),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(
                ["project_id"],
                ["cloud_migration_projects.id"],
                name="fk_cloud_migration_execution_jobs_project_id",
            ),
            sa.ForeignKeyConstraint(
                ["wave_id"],
                ["cloud_migration_waves.id"],
                name="fk_cloud_migration_execution_jobs_wave_id",
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "client_id",
                "idempotency_key",
                name="uq_cloud_migration_execution_job_client_idempotency",
            ),
        )
        for column in (
            "client_id",
            "project_id",
            "wave_id",
            "action",
            "status",
            "not_before",
            "lease_owner",
            "lease_expires_at",
            "created_at",
        ):
            op.create_index(
                f"ix_cloud_migration_execution_jobs_{column}",
                "cloud_migration_execution_jobs",
                [column],
            )

    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "cloud_migration_evidence_artifacts" not in tables:
        op.create_table(
            "cloud_migration_evidence_artifacts",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("client_id", sa.String(length=128), nullable=False),
            sa.Column("project_id", sa.String(length=36), nullable=False),
            sa.Column("wave_id", sa.String(length=36), nullable=False),
            sa.Column("job_id", sa.String(length=36), nullable=False),
            sa.Column("evidence_type", sa.String(length=64), nullable=False),
            sa.Column("content_sha256", sa.String(length=64), nullable=False),
            sa.Column("payload_json", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(
                ["job_id"],
                ["cloud_migration_execution_jobs.id"],
                name="fk_cloud_migration_evidence_artifacts_job_id",
            ),
            sa.PrimaryKeyConstraint("id"),
        )
        for column in ("client_id", "project_id", "wave_id", "job_id", "evidence_type", "created_at"):
            op.create_index(
                f"ix_cloud_migration_evidence_artifacts_{column}",
                "cloud_migration_evidence_artifacts",
                [column],
            )


def downgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "cloud_migration_evidence_artifacts" in tables:
        op.drop_table("cloud_migration_evidence_artifacts")
    if "cloud_migration_execution_jobs" in tables:
        op.drop_table("cloud_migration_execution_jobs")
