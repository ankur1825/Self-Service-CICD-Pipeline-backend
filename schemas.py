# schemas.py
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class Vulnerability(BaseModel):
    source: str
    target: str
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    vulnerability_id: str
    severity: str
    risk_score: float
    description: Optional[str] = None
    fixed_version: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    line: Optional[int] = None
    rule: Optional[str] = None
    status: Optional[str] = None
    predicted_severity: Optional[str] = None

class Application(BaseModel):
    name: str
    modules: Optional[List[str]] = []

class UserAccess(BaseModel):
    username: str
    applications: List[str]

class UploadPayload(BaseModel):
    application: str
    module: Optional[str] = None
    vulnerabilities: List[Vulnerability]
