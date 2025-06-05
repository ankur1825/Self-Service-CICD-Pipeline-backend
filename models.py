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
