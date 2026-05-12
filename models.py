from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

#Base = declarative_base()

class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    owner_email = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    repo_url = Column(String, unique=True)
    branch = Column(String)
    app_type = Column(String, default="unknown") 

    vulnerabilities = relationship("Vulnerability", back_populates="application")
    access_list = relationship("ApplicationUserAccess", back_populates="application")


class ApplicationUserAccess(Base):
    __tablename__ = "app_user_access"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, nullable=False)
    application_id = Column(Integer, ForeignKey("applications.id"))

    application = relationship("Application", back_populates="access_list")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"))
    target = Column(String, nullable=False)
    package_name = Column(String, nullable=True)
    installed_version = Column(String, nullable=True)
    vulnerability_id = Column(String, nullable=False)
    severity = Column(String, nullable=True)
    fixed_version = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    description = Column(Text, nullable=True)
    source = Column(String, default="Unknown")
    timestamp = Column(DateTime, default=datetime.utcnow)
    line = Column(Integer, nullable=True)
    rule = Column(String, nullable=True)
    status = Column(String, nullable=True)
    predicted_severity = Column(String, nullable=True)
    jenkins_job = Column(String)
    build_number = Column(Integer)
    jenkins_url = Column(String, nullable=True)

    application = relationship("Application", back_populates="vulnerabilities")


class EnvironmentCatalog(Base):
    __tablename__ = "environment_catalog"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False, index=True)
    display_name = Column(String, nullable=True)
    account_tier = Column(String, nullable=True)
    aws_account_id = Column(String, nullable=True)
    aws_region = Column(String, default="us-east-1")
    ecr_registry = Column(String, nullable=True)
    ecr_repository_template = Column(String, nullable=True)
    artifact_bucket = Column(String, nullable=True)
    client_aws_role_arn = Column(String, nullable=True)
    nonprod_aws_role_arn = Column(String, nullable=True)
    source_aws_role_arn = Column(String, nullable=True)
    target_aws_role_arn = Column(String, nullable=True)
    cluster_name = Column(String, nullable=True)
    namespace_strategy = Column(String, default="auto")
    namespace_template = Column(String, default="{client_id}-{project_name}-{env}")
    sns_topic_arn = Column(String, nullable=True)
    is_active = Column(Integer, default=1)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
