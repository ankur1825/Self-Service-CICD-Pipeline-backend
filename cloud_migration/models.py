from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from database import Base


class MigrationProject(Base):
    __tablename__ = "cloud_migration_projects"
    __table_args__ = (
        UniqueConstraint("client_id", "name", name="uq_cloud_migration_project_client_name"),
    )

    id = Column(String(36), primary_key=True)
    client_id = Column(String(128), nullable=False, index=True)
    name = Column(String(160), nullable=False)
    description = Column(Text, nullable=True)
    source_type = Column(String(32), nullable=False)
    target_provider = Column(String(16), nullable=False, default="aws")
    target_environment = Column(String(64), nullable=False)
    target_account_id = Column(String(64), nullable=False)
    source_endpoint_id = Column(
        String(36),
        ForeignKey("cloud_migration_endpoints.id", name="fk_cloud_migration_projects_source_endpoint_id"),
        nullable=True,
        index=True,
    )
    target_endpoint_id = Column(
        String(36),
        ForeignKey("cloud_migration_endpoints.id", name="fk_cloud_migration_projects_target_endpoint_id"),
        nullable=True,
        index=True,
    )
    status = Column(String(32), nullable=False, default="DRAFT", index=True)
    created_by = Column(String(256), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    waves = relationship(
        "MigrationWave",
        back_populates="project",
        cascade="all, delete-orphan",
        order_by="MigrationWave.created_at",
    )


class MigrationWave(Base):
    __tablename__ = "cloud_migration_waves"
    __table_args__ = (
        UniqueConstraint("project_id", "name", name="uq_cloud_migration_wave_project_name"),
    )

    id = Column(String(36), primary_key=True)
    project_id = Column(String(36), ForeignKey("cloud_migration_projects.id"), nullable=False, index=True)
    name = Column(String(160), nullable=False)
    migration_method = Column(String(32), nullable=False, default="mgn")
    migration_strategy = Column(String(32), nullable=False, default="rehost")
    transfer_profile_id = Column(
        String(36),
        ForeignKey("cloud_migration_transfer_profiles.id", name="fk_cloud_migration_waves_transfer_profile_id"),
        nullable=True,
        index=True,
    )
    source_region = Column(String(64), nullable=True)
    target_region = Column(String(64), nullable=False)
    maintenance_window = Column(String(160), nullable=True)
    status = Column(String(32), nullable=False, default="DRAFT", index=True)
    plan_version = Column(Integer, nullable=False, default=0)
    plan_summary = Column(Text, nullable=True)
    requested_by = Column(String(256), nullable=False)
    approved_by = Column(String(256), nullable=True)
    approval_comment = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    project = relationship("MigrationProject", back_populates="waves")
    workloads = relationship(
        "MigrationWorkload",
        back_populates="wave",
        cascade="all, delete-orphan",
        order_by="MigrationWorkload.created_at",
    )


class MigrationWorkload(Base):
    __tablename__ = "cloud_migration_workloads"
    __table_args__ = (
        UniqueConstraint("wave_id", "source_ref", name="uq_cloud_migration_workload_wave_source"),
    )

    id = Column(String(36), primary_key=True)
    wave_id = Column(String(36), ForeignKey("cloud_migration_waves.id"), nullable=False, index=True)
    source_ref = Column(String(256), nullable=False)
    hostname = Column(String(256), nullable=True)
    os_family = Column(String(32), nullable=True)
    source_instance_type = Column(String(64), nullable=True)
    target_instance_type = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="DISCOVERED", index=True)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    wave = relationship("MigrationWave", back_populates="workloads")


class MigrationAuditEvent(Base):
    __tablename__ = "cloud_migration_audit_events"

    id = Column(String(36), primary_key=True)
    client_id = Column(String(128), nullable=False, index=True)
    actor = Column(String(256), nullable=False)
    event_type = Column(String(96), nullable=False, index=True)
    entity_type = Column(String(64), nullable=False)
    entity_id = Column(String(36), nullable=False, index=True)
    payload_json = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)


class MigrationEndpoint(Base):
    __tablename__ = "cloud_migration_endpoints"
    __table_args__ = (
        UniqueConstraint("client_id", "name", name="uq_cloud_migration_endpoint_client_name"),
    )

    id = Column(String(36), primary_key=True)
    client_id = Column(String(128), nullable=False, index=True)
    name = Column(String(160), nullable=False)
    endpoint_role = Column(String(16), nullable=False)
    provider = Column(String(32), nullable=False, index=True)
    environment_name = Column(String(64), nullable=True)
    account_scope = Column(String(128), nullable=True)
    location = Column(String(128), nullable=True)
    identity_profile_ref = Column(String(256), nullable=True)
    network_profile_ref = Column(String(256), nullable=True)
    provider_config_json = Column(Text, nullable=True)
    status = Column(String(32), nullable=False, default="DRAFT", index=True)
    created_by = Column(String(256), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class MigrationTransferProfile(Base):
    __tablename__ = "cloud_migration_transfer_profiles"
    __table_args__ = (
        UniqueConstraint("client_id", "name", name="uq_cloud_migration_transfer_profile_client_name"),
    )

    id = Column(String(36), primary_key=True)
    client_id = Column(String(128), nullable=False, index=True)
    name = Column(String(160), nullable=False)
    adapter_key = Column(String(64), nullable=False, index=True)
    adapter_version = Column(String(32), nullable=False, default="v1alpha1")
    category = Column(String(32), nullable=False, default="replication")
    license_mode = Column(String(64), nullable=False, default="included")
    credential_ref = Column(String(256), nullable=True)
    configuration_json = Column(Text, nullable=True)
    enabled = Column(Integer, nullable=False, default=0, index=True)
    status = Column(String(32), nullable=False, default="DRAFT", index=True)
    created_by = Column(String(256), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
