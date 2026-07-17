from typing import List, Literal, Optional

from pydantic import BaseModel, Field


SourceType = Literal["aws-ec2", "external"]
MigrationMethod = Literal["mgn", "ami-copy"]


class MigrationProjectCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=160)
    description: Optional[str] = Field(default=None, max_length=4000)
    source_type: SourceType = "aws-ec2"
    target_provider: Literal["aws"] = "aws"
    target_environment: str = Field(..., min_length=2, max_length=64)


class MigrationWorkloadCreate(BaseModel):
    source_ref: str = Field(..., min_length=1, max_length=256)
    hostname: Optional[str] = Field(default=None, max_length=256)
    os_family: Optional[Literal["LINUX", "WINDOWS"]] = None
    source_instance_type: Optional[str] = Field(default=None, max_length=64)
    target_instance_type: Optional[str] = Field(default=None, max_length=64)


class MigrationWaveCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=160)
    migration_method: MigrationMethod = "mgn"
    source_region: Optional[str] = Field(default=None, max_length=64)
    target_region: Optional[str] = Field(default=None, max_length=64)
    maintenance_window: Optional[str] = Field(default=None, max_length=160)
    workloads: List[MigrationWorkloadCreate] = Field(..., min_items=1, max_items=500)


class MigrationWavePlanRequest(BaseModel):
    expected_version: Optional[int] = Field(default=None, ge=0)


class MigrationWaveApprovalRequest(BaseModel):
    expected_version: Optional[int] = Field(default=None, ge=1)
    comment: Optional[str] = Field(default=None, max_length=2000)
