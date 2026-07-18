"""Add provider-neutral endpoints and transfer profiles.

Revision ID: 20260718_0001
Revises:
Create Date: 2026-07-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260718_0001"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_names(table_name: str) -> set[str]:
    return {item["name"] for item in sa.inspect(op.get_bind()).get_columns(table_name)}


def _index_names(table_name: str) -> set[str]:
    return {item["name"] for item in sa.inspect(op.get_bind()).get_indexes(table_name)}


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())

    if "cloud_migration_endpoints" not in tables:
        op.create_table(
            "cloud_migration_endpoints",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("client_id", sa.String(length=128), nullable=False),
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("endpoint_role", sa.String(length=16), nullable=False),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("environment_name", sa.String(length=64), nullable=True),
            sa.Column("account_scope", sa.String(length=128), nullable=True),
            sa.Column("location", sa.String(length=128), nullable=True),
            sa.Column("identity_profile_ref", sa.String(length=256), nullable=True),
            sa.Column("network_profile_ref", sa.String(length=256), nullable=True),
            sa.Column("provider_config_json", sa.Text(), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
            sa.Column("created_by", sa.String(length=256), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("client_id", "name", name="uq_cloud_migration_endpoint_client_name"),
        )
        op.create_index("ix_cloud_migration_endpoints_client_id", "cloud_migration_endpoints", ["client_id"])
        op.create_index("ix_cloud_migration_endpoints_provider", "cloud_migration_endpoints", ["provider"])
        op.create_index("ix_cloud_migration_endpoints_status", "cloud_migration_endpoints", ["status"])

    if "cloud_migration_transfer_profiles" not in tables:
        op.create_table(
            "cloud_migration_transfer_profiles",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("client_id", sa.String(length=128), nullable=False),
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("adapter_key", sa.String(length=64), nullable=False),
            sa.Column("adapter_version", sa.String(length=32), nullable=False, server_default="v1alpha1"),
            sa.Column("category", sa.String(length=32), nullable=False, server_default="replication"),
            sa.Column("license_mode", sa.String(length=64), nullable=False, server_default="included"),
            sa.Column("credential_ref", sa.String(length=256), nullable=True),
            sa.Column("configuration_json", sa.Text(), nullable=True),
            sa.Column("enabled", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
            sa.Column("created_by", sa.String(length=256), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("client_id", "name", name="uq_cloud_migration_transfer_profile_client_name"),
        )
        op.create_index("ix_cloud_migration_transfer_profiles_client_id", "cloud_migration_transfer_profiles", ["client_id"])
        op.create_index("ix_cloud_migration_transfer_profiles_adapter_key", "cloud_migration_transfer_profiles", ["adapter_key"])
        op.create_index("ix_cloud_migration_transfer_profiles_enabled", "cloud_migration_transfer_profiles", ["enabled"])
        op.create_index("ix_cloud_migration_transfer_profiles_status", "cloud_migration_transfer_profiles", ["status"])

    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "cloud_migration_projects" in tables:
        columns = _column_names("cloud_migration_projects")
        with op.batch_alter_table("cloud_migration_projects") as batch_op:
            if "source_endpoint_id" not in columns:
                batch_op.add_column(sa.Column("source_endpoint_id", sa.String(length=36), nullable=True))
                batch_op.create_foreign_key(
                    "fk_cloud_migration_projects_source_endpoint_id",
                    "cloud_migration_endpoints",
                    ["source_endpoint_id"],
                    ["id"],
                )
                batch_op.create_index("ix_cloud_migration_projects_source_endpoint_id", ["source_endpoint_id"])
            if "target_endpoint_id" not in columns:
                batch_op.add_column(sa.Column("target_endpoint_id", sa.String(length=36), nullable=True))
                batch_op.create_foreign_key(
                    "fk_cloud_migration_projects_target_endpoint_id",
                    "cloud_migration_endpoints",
                    ["target_endpoint_id"],
                    ["id"],
                )
                batch_op.create_index("ix_cloud_migration_projects_target_endpoint_id", ["target_endpoint_id"])

    if "cloud_migration_waves" in tables:
        columns = _column_names("cloud_migration_waves")
        with op.batch_alter_table("cloud_migration_waves") as batch_op:
            if "migration_strategy" not in columns:
                batch_op.add_column(
                    sa.Column("migration_strategy", sa.String(length=32), nullable=False, server_default="rehost")
                )
            if "transfer_profile_id" not in columns:
                batch_op.add_column(sa.Column("transfer_profile_id", sa.String(length=36), nullable=True))
                batch_op.create_foreign_key(
                    "fk_cloud_migration_waves_transfer_profile_id",
                    "cloud_migration_transfer_profiles",
                    ["transfer_profile_id"],
                    ["id"],
                )
                batch_op.create_index("ix_cloud_migration_waves_transfer_profile_id", ["transfer_profile_id"])


def downgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())

    if "cloud_migration_waves" in tables:
        columns = _column_names("cloud_migration_waves")
        indexes = _index_names("cloud_migration_waves")
        with op.batch_alter_table("cloud_migration_waves") as batch_op:
            if "transfer_profile_id" in columns:
                if "ix_cloud_migration_waves_transfer_profile_id" in indexes:
                    batch_op.drop_index("ix_cloud_migration_waves_transfer_profile_id")
                batch_op.drop_constraint("fk_cloud_migration_waves_transfer_profile_id", type_="foreignkey")
                batch_op.drop_column("transfer_profile_id")
            if "migration_strategy" in columns:
                batch_op.drop_column("migration_strategy")

    if "cloud_migration_projects" in tables:
        columns = _column_names("cloud_migration_projects")
        indexes = _index_names("cloud_migration_projects")
        with op.batch_alter_table("cloud_migration_projects") as batch_op:
            for column, constraint, index in (
                (
                    "target_endpoint_id",
                    "fk_cloud_migration_projects_target_endpoint_id",
                    "ix_cloud_migration_projects_target_endpoint_id",
                ),
                (
                    "source_endpoint_id",
                    "fk_cloud_migration_projects_source_endpoint_id",
                    "ix_cloud_migration_projects_source_endpoint_id",
                ),
            ):
                if column in columns:
                    if index in indexes:
                        batch_op.drop_index(index)
                    batch_op.drop_constraint(constraint, type_="foreignkey")
                    batch_op.drop_column(column)

    if "cloud_migration_transfer_profiles" in tables:
        op.drop_table("cloud_migration_transfer_profiles")
    if "cloud_migration_endpoints" in tables:
        op.drop_table("cloud_migration_endpoints")
