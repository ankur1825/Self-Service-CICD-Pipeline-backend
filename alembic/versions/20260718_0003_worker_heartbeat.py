"""Add observed execution worker heartbeat.

Revision ID: 20260718_0003
Revises: 20260718_0002
Create Date: 2026-07-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260718_0003"
down_revision: Union[str, Sequence[str], None] = "20260718_0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "cloud_migration_worker_heartbeats" in tables:
        return
    op.create_table(
        "cloud_migration_worker_heartbeats",
        sa.Column("worker_id", sa.String(length=256), nullable=False),
        sa.Column("client_id", sa.String(length=128), nullable=False),
        sa.Column("execution_mode", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="RUNNING"),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("worker_id"),
    )
    op.create_index(
        "ix_cloud_migration_worker_heartbeats_client_id",
        "cloud_migration_worker_heartbeats",
        ["client_id"],
    )
    op.create_index(
        "ix_cloud_migration_worker_heartbeats_last_seen_at",
        "cloud_migration_worker_heartbeats",
        ["last_seen_at"],
    )


def downgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "cloud_migration_worker_heartbeats" in tables:
        op.drop_table("cloud_migration_worker_heartbeats")
