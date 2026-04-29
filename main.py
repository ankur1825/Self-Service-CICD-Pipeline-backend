from fastapi import FastAPI, Request, Depends, Header, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import os
import requests
from ldap3 import Server, Connection, ALL, SUBTREE
import logging
import json
import hmac
import hashlib
from html import escape

from database import SessionLocal, engine, Base
from models import Application, ApplicationUserAccess, Vulnerability
from enterprise.licensing import (
    LicenseValidationError,
    default_license_from_env,
    license_summary,
    merge_request_license,
    validate_license,
)

DATABASE_PATH = "/app/data/app.db"  # This path must match your Helm `mountPath`

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(root_path="/pipeline/api")

Base.metadata.create_all(bind=engine)

# Jenkins configuration
JENKINS_URL = os.getenv("JENKINS_URL", "https://horizonrelevance.com/jenkins")
JENKINS_USER = os.getenv("JENKINS_USER")
JENKINS_TOKEN = os.getenv("JENKINS_TOKEN")

# GitHub webhook secret
GITHUB_WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]

# LDAP configuration
LDAP_SERVER = os.getenv("LDAP_SERVER", "ldap://openldap.horizon-relevance-dev.svc.cluster.local:389")
LDAP_USER = os.getenv("LDAP_USER", "cn=admin,dc=horizonrelevance,dc=local")
LDAP_PASSWORD = os.getenv("LDAP_MANAGER_PASSWORD")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "ou=users,dc=horizonrelevance,dc=local")
SEARCH_FILTER = os.getenv("LDAP_SEARCH_FILTER", "(objectClass=inetOrgPerson)")
LDAP_UID_ATTRIBUTE = os.getenv("LDAP_UID_ATTRIBUTE", "uid")
LDAP_DISPLAY_NAME_ATTRIBUTE = os.getenv("LDAP_DISPLAY_NAME_ATTRIBUTE", "displayName")
LDAP_MAIL_ATTRIBUTE = os.getenv("LDAP_MAIL_ATTRIBUTE", "mail")

# CORS setup for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://horizonrelevance.com/pipeline"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class PipelineRequest(BaseModel):
    project_name: str
    app_type: str
    repo_url: str
    branch: str
    ENABLE_SONARQUBE: bool
    ENABLE_OPA: bool
    ENABLE_TRIVY: bool
    requestedBy: str

class DevopsPipelineRequest(BaseModel):
    requestedBy: str
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    license_key: Optional[str] = None
    license_signature: Optional[str] = None
    license_expires_at: Optional[str] = None
    license_type: Optional[str] = None
    enabled_pipelines: Optional[List[str]] = None
    enabled_features: Optional[List[str]] = None
    allowed_environments: Optional[List[str]] = None
    project_name: str
    project_type: str
    repo_type: str
    repo_url: str
    branch: str = "main"
    ENABLE_SONARQUBE: bool = True
    ENABLE_CHECKMARX: bool = False
    checkmarx_team: Optional[str] = None
    ENABLE_SOAPUI: bool = False
    ENABLE_JMETER: bool = False
    ENABLE_SELENIUM: bool = False
    ENABLE_NEWMAN: bool = False
    ENABLE_TRIVY: bool = False
    target_env: str = "EKS-NONPROD"
    notify_email: Optional[str] = None
    aws_region: str = "us-east-1"
    ecr_registry: str
    ecr_repository: str
    artifact_bucket: str
    client_aws_role_arn: Optional[str] = None
    enable_notifications: bool = False
    sns_topic_arn: Optional[str] = None

class LicenseValidationRequest(BaseModel):
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    license_key: Optional[str] = None
    license_signature: Optional[str] = None
    license_expires_at: Optional[str] = None
    license_type: Optional[str] = None
    enabled_pipelines: Optional[List[str]] = None
    enabled_features: Optional[List[str]] = None
    allowed_environments: Optional[List[str]] = None
    pipeline_name: str = "Devops Pipeline"
    target_env: str = "EKS-NONPROD"
    requested_features: List[str] = []

class TriggerRequest(BaseModel):
    project_name: str

class VulnerabilityModel(BaseModel):
    target: str
    package_name: str
    installed_version: str
    vulnerability_id: str
    severity: str
    fixed_version: Optional[str] = None
    risk_score: float = 0.0
    description: Optional[str] = None
    source: Optional[str] = "Trivy"
    timestamp: Optional[str] = None
    line: Optional[int] = None
    rule: Optional[str] = None
    status: Optional[str] = None
    predictedSeverity: Optional[str] = None
    jenkins_job: str
    build_number: int
    jenkins_url: Optional[str] = None

class VulnerabilityUpload(BaseModel):
    vulnerabilities: List[VulnerabilityModel]

class OPARiskModel(BaseModel):
    target: str
    violation: str
    severity: str
    risk_score: float
    package_name: Optional[str] = "OPA Policy"       
    installed_version: Optional[str] = "N/A"  
    source: Optional[str] = "OPA"    
    description: Optional[str] = ""
    remediation: Optional[str] = ""
    jenkins_job: Optional[str] = None
    build_number: Optional[int] = None
    jenkins_url: Optional[str] = None

class OPARiskUpload(BaseModel):
    application: str
    risks: List[OPARiskModel]

class UploadPayload(BaseModel):
    application: str
    requestedBy: str
    repo_url: str
    jenkins_url: str
    jenkins_job: str
    build_number: int
    vulnerabilities: List[VulnerabilityModel]

class RegisterAppRequest(BaseModel):
    name: str
    description: Optional[str] = None
    owner_email: str
    repo_url: str 
    branch: str = "main"

class GrantAccessRequest(BaseModel):
    user_email: str
    application: str    

def requested_devops_features(request: DevopsPipelineRequest) -> List[str]:
    features = ["build", "artifact_publish"]
    if request.ENABLE_SONARQUBE:
        features.append("code_scan")
    if request.ENABLE_TRIVY:
        features.append("image_scan")
    if request.ENABLE_CHECKMARX:
        features.append("static_application_security")
    if request.ENABLE_SOAPUI or request.ENABLE_JMETER or request.ENABLE_SELENIUM or request.ENABLE_NEWMAN:
        features.append("test_suites")
    if "PROD" in (request.target_env or "").upper():
        features.append("prod_deploy")
    if request.enable_notifications:
        features.append("notifications")
    return features

@app.get("/license/status")
def get_license_status():
    license_doc = default_license_from_env()
    try:
        validated = validate_license(
            license_doc,
            pipeline_name="Devops Pipeline",
            target_env="EKS-NONPROD",
            requested_features=[],
        )
        return license_summary(validated)
    except LicenseValidationError as exc:
        license_doc["status"] = "invalid"
        summary = license_summary(license_doc)
        summary["error"] = str(exc)
        return JSONResponse(status_code=403, content=summary)

@app.post("/license/validate")
def validate_enterprise_license(request: LicenseValidationRequest):
    license_doc = merge_request_license(request.dict())
    try:
        validated = validate_license(
            license_doc,
            pipeline_name=request.pipeline_name,
            target_env=request.target_env,
            requested_features=request.requested_features,
        )
        return license_summary(validated)
    except LicenseValidationError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc), "status": "invalid"})

@app.post("/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username")
    password = body.get("password")
    if not username or not password:
        return JSONResponse(status_code=400, content={"error": "Username and password required"})
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        search_conn = Connection(server, user=LDAP_USER, password=LDAP_PASSWORD, auto_bind=True)
        search_conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=f"({LDAP_UID_ATTRIBUTE}={username})",
            search_scope=SUBTREE,
            attributes=[LDAP_DISPLAY_NAME_ATTRIBUTE, LDAP_MAIL_ATTRIBUTE, LDAP_UID_ATTRIBUTE]
        )
        if not search_conn.entries:
            return JSONResponse(status_code=401, content={"error": "User not found"})

        user_entry = search_conn.entries[0]
        user_dn = str(user_entry.entry_dn)
        display_name = str(user_entry[LDAP_DISPLAY_NAME_ATTRIBUTE]) if LDAP_DISPLAY_NAME_ATTRIBUTE in user_entry else username
        email = str(user_entry[LDAP_MAIL_ATTRIBUTE]) if LDAP_MAIL_ATTRIBUTE in user_entry else ""
        search_conn.unbind()

        auth_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        auth_conn.unbind()

        return {"username": username, "fullName": display_name, "email": email}

    except Exception as e:
        return JSONResponse(status_code=401, content={"error": "Invalid credentials or server error"})

@app.get("/get_ldap_users")
def get_ldap_users():
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(server, user=LDAP_USER, password=LDAP_PASSWORD, auto_bind=True)
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=SEARCH_FILTER,
            search_scope=SUBTREE,
            attributes=[LDAP_UID_ATTRIBUTE, LDAP_DISPLAY_NAME_ATTRIBUTE, LDAP_MAIL_ATTRIBUTE]
        )
        users = []
        seen = set()
        for entry in conn.entries:
            uid = str(entry[LDAP_UID_ATTRIBUTE]) if LDAP_UID_ATTRIBUTE in entry else None
            display_name = str(entry[LDAP_DISPLAY_NAME_ATTRIBUTE]) if LDAP_DISPLAY_NAME_ATTRIBUTE in entry else uid
            email = str(entry[LDAP_MAIL_ATTRIBUTE]) if LDAP_MAIL_ATTRIBUTE in entry else ""
            if uid and uid not in seen:
                users.append({"username": uid, "fullName": display_name, "email": email})
                seen.add(uid)
        conn.unbind()
        return JSONResponse(content=users)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Failed to fetch LDAP users"})
    
@app.get("/my_applications")
def get_user_applications(email: str, db: Session = Depends(get_db)):
    try:
        print(f"[DEBUG] Incoming email: {email}")
        if email in ["ankur.kashyap@horizonrelevance.com"]:
            apps = db.query(Application.name).all()
            print(f"[DEBUG] Admin access - apps: {apps}")
            return [a.name for a in apps]

        apps = db.query(Application.name).join(ApplicationUserAccess).filter(
            ApplicationUserAccess.user_email == email
        ).all()
        print(f"[DEBUG] User apps: {apps}")
        return [a.name for a in apps]

    except Exception as e:
        print(f"[ERROR] in /my_applications: {e}")
        return JSONResponse(status_code=500, content={"error": "Failed to call backend"})


@app.post("/pipeline")
def create_pipeline(request: PipelineRequest):
    job_config = f"""
<flow-definition plugin="workflow-job">
  <description>Dynamic Jenkins Pipeline for {request.project_name}</description>
  <properties>
    <hudson.model.ParametersDefinitionProperty>
      <parameterDefinitions>
        <hudson.model.StringParameterDefinition>
          <name>APP_TYPE</name>
          <defaultValue>{request.app_type}</defaultValue>
          <description>Application Type</description>
        </hudson.model.StringParameterDefinition>
        <hudson.model.StringParameterDefinition>
          <name>REPO_URL</name>
          <defaultValue>{request.repo_url}</defaultValue>
          <description>Git Repository URL</description>
        </hudson.model.StringParameterDefinition>
        <hudson.model.StringParameterDefinition>
          <name>BRANCH</name>
          <defaultValue>{request.branch}</defaultValue>
          <description>Git Branch</description>
        </hudson.model.StringParameterDefinition>
        <hudson.model.StringParameterDefinition>
          <name>CREDENTIALS_ID</name>
          <defaultValue>github-token</defaultValue>
          <description>Jenkins GitHub Credential ID</description>
        </hudson.model.StringParameterDefinition>
        <hudson.model.BooleanParameterDefinition>
          <name>ENABLE_SONARQUBE</name>
          <defaultValue>{str(request.ENABLE_SONARQUBE).lower()}</defaultValue>
          <description>Enable SonarQube Scan</description>
        </hudson.model.BooleanParameterDefinition>
        <hudson.model.BooleanParameterDefinition>
          <name>ENABLE_OPA</name>
          <defaultValue>{str(request.ENABLE_OPA).lower()}</defaultValue>
          <description>Enable OPA Scan</description>
        </hudson.model.BooleanParameterDefinition>
        <hudson.model.BooleanParameterDefinition>
          <name>ENABLE_TRIVY</name>
          <defaultValue>{str(request.ENABLE_TRIVY).lower()}</defaultValue>
          <description>Enable Trivy Scan</description>
        </hudson.model.BooleanParameterDefinition>
      </parameterDefinitions>
    </hudson.model.ParametersDefinitionProperty>
  </properties>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
    <script>
@Library('jenkins-shared-library@main') _
main_template([
  APP_TYPE: "${{APP_TYPE}}",
  REPO_URL: "${{REPO_URL}}",
  BRANCH: "${{BRANCH}}",
  CREDENTIALS_ID: "${{CREDENTIALS_ID}}",
  ENABLE_SONARQUBE: "${{ENABLE_SONARQUBE}}",
  ENABLE_OPA: "${{ENABLE_OPA}}",
  ENABLE_TRIVY: "${{ENABLE_TRIVY}}"
])
    </script>
    <sandbox>true</sandbox>
  </definition>
</flow-definition>
"""
    create_response = requests.post(
        f"{JENKINS_URL}/createItem?name={request.project_name}",
        headers={"Content-Type": "application/xml"},
        auth=(JENKINS_USER, JENKINS_TOKEN),
        data=job_config,
        verify=False
    )

    build_response = requests.post(
        f"{JENKINS_URL}/job/{request.project_name}/buildWithParameters",
        auth=(JENKINS_USER, JENKINS_TOKEN),
        params={
            "APP_TYPE": request.app_type,
            "REPO_URL": request.repo_url,
            "BRANCH": request.branch,
            "CREDENTIALS_ID": "github-token",
            "ENABLE_SONARQUBE": str(request.ENABLE_SONARQUBE).lower(),
            "ENABLE_OPA": str(request.ENABLE_OPA).lower(),
            "ENABLE_TRIVY": str(request.ENABLE_TRIVY).lower()
        },
        verify=False
    )

    return {
        "status": "Pipeline created and triggered",
        "create_response_code": create_response.status_code,
        "build_response_code": build_response.status_code
    }

@app.post("/devops/pipeline")
def create_devops_pipeline(request: DevopsPipelineRequest):
    allowed_project_types = {
        "Docker",
        "Angular",
        "SpringBoot",
        "SpringBoot-Java11",
        "NodeJs",
        "WebComponent",
    }
    if request.project_type not in allowed_project_types:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Unsupported project_type",
                "supported_project_types": sorted(allowed_project_types),
            },
        )

    job_name = request.project_name.strip()
    if not job_name:
        return JSONResponse(status_code=400, content={"error": "project_name is required"})

    license_doc = merge_request_license(request.dict())
    try:
        validated_license = validate_license(
            license_doc,
            pipeline_name="Devops Pipeline",
            target_env=request.target_env,
            requested_features=requested_devops_features(request),
        )
    except LicenseValidationError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc), "status": "license_denied"})

    license_summary_doc = license_summary(validated_license)
    enabled_pipelines = ",".join(validated_license.get("enabled_pipelines") or [])
    enabled_features = ",".join(validated_license.get("enabled_features") or [])
    allowed_environments = ",".join(validated_license.get("allowed_environments") or [])

    values = {
        "CLIENT_ID": str(validated_license.get("client_id") or "").strip(),
        "CLIENT_NAME": str(validated_license.get("client_name") or "").strip(),
        "LICENSE_TYPE": str(validated_license.get("license_type") or "").strip(),
        "LICENSE_EXPIRES_AT": str(validated_license.get("expires_at") or "").strip(),
        "LICENSED_PIPELINES": enabled_pipelines,
        "LICENSED_FEATURES": enabled_features,
        "LICENSED_ENVIRONMENTS": allowed_environments,
        "LICENSE_VALIDATION_MODE": str(validated_license.get("validation_mode") or "unknown"),
        "PROJECT_NAME": job_name,
        "PROJECT_TYPE": request.project_type,
        "REPO_TYPE": request.repo_type,
        "REPO_URL": request.repo_url.strip(),
        "BRANCH": request.branch.strip() or "main",
        "CREDENTIALS_ID": "github-token",
        "PIPELINE_KIND": "DEVOPS",
        "SERVICE_NAME": "Devops Pipeline",
        "REQUESTED_BY": request.requestedBy,
        "ENABLE_SONARQUBE": str(request.ENABLE_SONARQUBE).lower(),
        "ENABLE_CHECKMARX": str(request.ENABLE_CHECKMARX).lower(),
        "CHECKMARX_TEAM": (request.checkmarx_team or "").strip(),
        "ENABLE_SOAPUI": str(request.ENABLE_SOAPUI).lower(),
        "ENABLE_JMETER": str(request.ENABLE_JMETER).lower(),
        "ENABLE_SELENIUM": str(request.ENABLE_SELENIUM).lower(),
        "ENABLE_NEWMAN": str(request.ENABLE_NEWMAN).lower(),
        "ENABLE_TRIVY": str(request.ENABLE_TRIVY).lower(),
        "ENABLE_OPA": "false",
        "TARGET_ENV": request.target_env,
        "NOTIFY_EMAIL": (request.notify_email or "").strip(),
        "AWS_REGION": request.aws_region.strip() or "us-east-1",
        "ECR_REGISTRY": request.ecr_registry.strip(),
        "ECR_REPOSITORY": request.ecr_repository.strip(),
        "ARTIFACT_BUCKET": request.artifact_bucket.strip(),
        "CLIENT_AWS_ROLE_ARN": (request.client_aws_role_arn or "").strip(),
        "ENABLE_NOTIFICATIONS": str(request.enable_notifications).lower(),
        "SNS_TOPIC_ARN": (request.sns_topic_arn or "").strip(),
    }
    xml_values = {k: escape(v, quote=True) for k, v in values.items()}

    bool_param_names = [
        "ENABLE_SONARQUBE",
        "ENABLE_CHECKMARX",
        "ENABLE_SOAPUI",
        "ENABLE_JMETER",
        "ENABLE_SELENIUM",
        "ENABLE_NEWMAN",
        "ENABLE_TRIVY",
        "ENABLE_OPA",
        "ENABLE_NOTIFICATIONS",
    ]
    string_param_names = [
        "CLIENT_ID",
        "CLIENT_NAME",
        "LICENSE_TYPE",
        "LICENSE_EXPIRES_AT",
        "LICENSED_PIPELINES",
        "LICENSED_FEATURES",
        "LICENSED_ENVIRONMENTS",
        "LICENSE_VALIDATION_MODE",
        "PROJECT_NAME",
        "PROJECT_TYPE",
        "REPO_TYPE",
        "REPO_URL",
        "BRANCH",
        "CREDENTIALS_ID",
        "PIPELINE_KIND",
        "SERVICE_NAME",
        "REQUESTED_BY",
        "CHECKMARX_TEAM",
        "TARGET_ENV",
        "NOTIFY_EMAIL",
        "AWS_REGION",
        "ECR_REGISTRY",
        "ECR_REPOSITORY",
        "ARTIFACT_BUCKET",
        "CLIENT_AWS_ROLE_ARN",
        "SNS_TOPIC_ARN",
    ]

    parameter_definitions = []
    for name in string_param_names:
        parameter_definitions.append(f"""
        <hudson.model.StringParameterDefinition>
          <name>{name}</name>
          <defaultValue>{xml_values[name]}</defaultValue>
          <description>{name}</description>
        </hudson.model.StringParameterDefinition>""")
    for name in bool_param_names:
        parameter_definitions.append(f"""
        <hudson.model.BooleanParameterDefinition>
          <name>{name}</name>
          <defaultValue>{xml_values[name]}</defaultValue>
          <description>{name}</description>
        </hudson.model.BooleanParameterDefinition>""")

    job_config = f"""
<flow-definition plugin="workflow-job">
  <description>Devops Pipeline for {xml_values["PROJECT_NAME"]}</description>
  <properties>
    <hudson.model.ParametersDefinitionProperty>
      <parameterDefinitions>
        {''.join(parameter_definitions)}
      </parameterDefinitions>
    </hudson.model.ParametersDefinitionProperty>
  </properties>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
    <script>
@Library('jenkins-shared-library@main') _
main_template([
  CLIENT_ID: "${{CLIENT_ID}}",
  CLIENT_NAME: "${{CLIENT_NAME}}",
  LICENSE_TYPE: "${{LICENSE_TYPE}}",
  LICENSE_EXPIRES_AT: "${{LICENSE_EXPIRES_AT}}",
  LICENSED_PIPELINES: "${{LICENSED_PIPELINES}}",
  LICENSED_FEATURES: "${{LICENSED_FEATURES}}",
  LICENSED_ENVIRONMENTS: "${{LICENSED_ENVIRONMENTS}}",
  LICENSE_VALIDATION_MODE: "${{LICENSE_VALIDATION_MODE}}",
  PROJECT_NAME: "${{PROJECT_NAME}}",
  PROJECT_TYPE: "${{PROJECT_TYPE}}",
  REPO_TYPE: "${{REPO_TYPE}}",
  REPO_URL: "${{REPO_URL}}",
  BRANCH: "${{BRANCH}}",
  CREDENTIALS_ID: "${{CREDENTIALS_ID}}",
  PIPELINE_KIND: "${{PIPELINE_KIND}}",
  SERVICE_NAME: "${{SERVICE_NAME}}",
  REQUESTED_BY: "${{REQUESTED_BY}}",
  ENABLE_SONARQUBE: "${{ENABLE_SONARQUBE}}",
  ENABLE_CHECKMARX: "${{ENABLE_CHECKMARX}}",
  CHECKMARX_TEAM: "${{CHECKMARX_TEAM}}",
  ENABLE_SOAPUI: "${{ENABLE_SOAPUI}}",
  ENABLE_JMETER: "${{ENABLE_JMETER}}",
  ENABLE_SELENIUM: "${{ENABLE_SELENIUM}}",
  ENABLE_NEWMAN: "${{ENABLE_NEWMAN}}",
  ENABLE_TRIVY: "${{ENABLE_TRIVY}}",
  ENABLE_OPA: "${{ENABLE_OPA}}",
  TARGET_ENV: "${{TARGET_ENV}}",
  NOTIFY_EMAIL: "${{NOTIFY_EMAIL}}",
  AWS_REGION: "${{AWS_REGION}}",
  ECR_REGISTRY: "${{ECR_REGISTRY}}",
  ECR_REPOSITORY: "${{ECR_REPOSITORY}}",
  ARTIFACT_BUCKET: "${{ARTIFACT_BUCKET}}",
  CLIENT_AWS_ROLE_ARN: "${{CLIENT_AWS_ROLE_ARN}}",
  ENABLE_NOTIFICATIONS: "${{ENABLE_NOTIFICATIONS}}",
  SNS_TOPIC_ARN: "${{SNS_TOPIC_ARN}}"
])
    </script>
    <sandbox>true</sandbox>
  </definition>
</flow-definition>
"""

    job_url = f"{JENKINS_URL}/job/{job_name}/api/json"
    job_check = requests.get(job_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    if job_check.status_code == 200:
        config_response = requests.post(
            f"{JENKINS_URL}/job/{job_name}/config.xml",
            headers={"Content-Type": "application/xml"},
            auth=(JENKINS_USER, JENKINS_TOKEN),
            data=job_config,
            verify=False,
        )
        create_status = "updated"
        create_response_code = config_response.status_code
    else:
        create_response = requests.post(
            f"{JENKINS_URL}/createItem?name={job_name}",
            headers={"Content-Type": "application/xml"},
            auth=(JENKINS_USER, JENKINS_TOKEN),
            data=job_config,
            verify=False,
        )
        create_status = "created"
        create_response_code = create_response.status_code

    build_response = requests.post(
        f"{JENKINS_URL}/job/{job_name}/buildWithParameters",
        auth=(JENKINS_USER, JENKINS_TOKEN),
        params=values,
        verify=False,
    )

    return {
        "status": f"Devops pipeline {create_status} and triggered",
        "project_name": job_name,
        "project_type": request.project_type,
        "license": license_summary_doc,
        "create_response_code": create_response_code,
        "build_response_code": build_response.status_code,
    }

@app.post("/pipeline/trigger")
def trigger_existing_pipeline(request: TriggerRequest):
    job_url = f"{JENKINS_URL}/job/{request.project_name}/api/json"
    job_check = requests.get(job_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    if job_check.status_code != 200:
        return {"status": "Job not found", "message": f"Pipeline '{request.project_name}' does not exist."}
    build_url = f"{JENKINS_URL}/job/{request.project_name}/build"
    build_trigger = requests.post(build_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    return {"status": "Build triggered", "project_name": request.project_name, "code": build_trigger.status_code}

@app.get("/pipeline/logs/{job_name}/{build_number}")
def get_console_logs(job_name: str, build_number: int):
    log_url = f"{JENKINS_URL}/job/{job_name}/{build_number}/logText/progressiveText"
    response = requests.get(log_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    return {"build_number": build_number, "job_name": job_name, "logs": response.text}

#vulnerabilities_store = []

# @app.post("/vulnerabilities")
# async def upload_vulnerabilities(payload: VulnerabilityUpload, db: Session = Depends(get_db)):
#     count = 0
#     default_app_name = "webserice-application"

#     # Ensure application exists or create a dummy entry
#     app_entry = db.query(Application).filter_by(name=default_app_name).first()
#     if not app_entry:
#         app_entry = Application(name=default_app_name, description="Auto-created", owner_email="auto@horizonrelevance.com")
#         db.add(app_entry)
#         db.commit()
#         db.refresh(app_entry)

#     for v in payload.vulnerabilities:
#         vuln = Vulnerability(
#             application_id=app_entry.id,
#             target=v.target,
#             package_name=v.package_name,
#             installed_version=v.installed_version,
#             vulnerability_id=v.vulnerability_id,
#             severity=v.severity,
#             fixed_version=v.fixed_version,
#             risk_score=v.risk_score,
#             description=v.description,
#             source=v.source,
#             timestamp=v.timestamp or datetime.utcnow(),
#             line=v.line,
#             rule=v.rule,
#             status=v.status,
#             predicted_severity=v.predictedSeverity,
#             jenkins_job=v.jenkins_job,
#             build_number=v.build_number,
#             jenkins_url=v.jenkins_url
#         )
#         db.add(vuln)
#         count += 1
#     db.commit()
#     return {"status": "uploaded", "count": count}

# GET: return only authorized vulnerabilities
@app.get("/vulnerabilities")
def get_vulnerabilities(
    email: str,
    application: Optional[str] = None,
    source: Optional[str] = None,
    db: Session = Depends(get_db)
):
    if email == "ankur.kashyap@horizonrelevance.com":
        query = db.query(Vulnerability)
    else:
        app_ids = db.query(ApplicationUserAccess.application_id).filter_by(user_email=email).all()
        allowed_ids = [a.application_id for a in app_ids]
        query = db.query(Vulnerability).filter(Vulnerability.application_id.in_(allowed_ids))

    if application:
        app_entry = db.query(Application).filter_by(name=application).first()
        if app_entry:
            query = query.filter(Vulnerability.application_id == app_entry.id)

    if source:
        query = query.filter_by(source=source)

    results = query.order_by(Vulnerability.timestamp.desc()).all()

    return [serialize_security_finding(v) for v in results]

@app.get("/security/findings")
def get_security_findings(
    email: str,
    application: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    findings = get_vulnerabilities(email=email, application=application, db=db)
    if category:
        findings = [f for f in findings if f.get("category") == category]
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.upper()]
    return findings

@app.delete("/vulnerabilities/clear")
def clear_vulnerabilities(db: Session = Depends(get_db)):
    deleted = db.query(Vulnerability).delete()
    db.commit()
    return {"status": "cleared", "deleted_records": deleted}

@app.post("/opa/risks/")
async def upload_opa_risks(payload: OPARiskUpload, db: Session = Depends(get_db)):
    try:
        logger.info(f"Received OPA risks for application: {payload.application}")
        logger.debug("Raw payload: %s", payload.dict())

        app_name = payload.application.strip()
        if not app_name:
            return JSONResponse(status_code=400, content={"error": "Application name is required"})

        # Ensure application exists
        app_entry = db.query(Application).filter_by(name=app_name).first()
        if not app_entry:
            logger.info(f"Creating new application entry: {app_name}")
            app_entry = Application(
                name=app_name,
                description="Auto-created",
                owner_email="ankur.kashyap@horizonrelevance.com"
            )
            db.add(app_entry)
            db.commit()
            db.refresh(app_entry)

        count = 0
        for risk in payload.risks:
            if not risk.violation:
                logger.warning(f"Skipping risk without violation: {risk}")
                continue

            vuln = Vulnerability(
                application_id=app_entry.id,
                target=risk.target,
                package_name=risk.package_name or "OPA Policy",
                installed_version=risk.installed_version or "N/A",
                vulnerability_id=risk.violation.strip(),
                severity=risk.severity.strip().upper(),
                fixed_version=risk.remediation or "Review policy",
                risk_score=risk.risk_score,
                description=risk.description or risk.violation,
                source=risk.source or "OPA", 
                jenkins_job=risk.jenkins_job,
                build_number=risk.build_number,
                jenkins_url=risk.jenkins_url,
                timestamp=datetime.utcnow()
            )
            db.add(vuln)
            count += 1

        db.commit()
        logger.info(f"Successfully stored {count} OPA-Kubernetes risks.")
        return {"status": "success", "received_count": count}

    except Exception as e:
        logger.exception("Failed to upload OPA risks")
        return JSONResponse(status_code=500, content={"error": "Server error while processing OPA risks"})


def get_dynamic_fix(violation: str) -> str:
    violation = violation.lower()
    if "root user" in violation:
        return "Use a non-root USER in Dockerfile"
    elif "ssh port" in violation:
        return "Avoid exposing port 22 unless explicitly needed"
    elif "privileged" in violation:
        return "Set privileged: false in your container configuration"
    elif "capabilities" in violation:
        return "Drop all Linux capabilities and add only required ones"
    elif "no read-only" in violation or "writable" in violation:
        return "Set filesystem to read-only using readOnlyRootFilesystem"
    else:
        return "Review OPA policy and secure container accordingly"

SECURITY_CATEGORY_BY_SOURCE = {
    "TRIVY": "Container Vulnerability",
    "SONARQUBE": "Code Security Finding",
    "OPA": "Policy Violation",
    "OPA-KUBERNETES": "Policy Violation",
    "CHECKMARX": "Static Code Security Finding",
}

def normalize_security_category(source: Optional[str], package_name: Optional[str], vulnerability_id: Optional[str]) -> str:
    source_key = (source or "").strip().upper()
    if source_key in SECURITY_CATEGORY_BY_SOURCE:
        return SECURITY_CATEGORY_BY_SOURCE[source_key]
    if (package_name or "").lower().endswith("policy") or "policy" in (vulnerability_id or "").lower():
        return "Policy Violation"
    return "Security Finding"

def normalize_remediation(v: Vulnerability) -> str:
    if v.fixed_version and v.fixed_version not in {"N/A", "None"}:
        if v.fixed_version.lower().startswith(("review", "use ", "avoid ", "set ", "drop ")):
            return v.fixed_version
        return f"Upgrade {v.package_name or 'the affected component'} to {v.fixed_version} or later."
    if v.description:
        return get_dynamic_fix(v.description)
    return "Review the affected component, validate exploitability, and apply the recommended vendor fix."

def serialize_security_finding(v: Vulnerability) -> dict:
    category = normalize_security_category(v.source, v.package_name, v.vulnerability_id)
    component = v.package_name or "Application"
    title = v.vulnerability_id or v.rule or "Security finding"
    fingerprint_source = "|".join([
        str(v.application_id or ""),
        category,
        component,
        title,
        v.target or "",
        str(v.line or ""),
    ])
    finding_id = hashlib.sha256(fingerprint_source.encode()).hexdigest()[:16]
    return {
        "finding_id": finding_id,
        "category": category,
        "target": v.target,
        "affected_component": component,
        "package_name": v.package_name,
        "installed_version": v.installed_version,
        "vulnerability_id": title,
        "severity": (v.severity or "UNKNOWN").upper(),
        "fixed_version": v.fixed_version,
        "remediation": normalize_remediation(v),
        "risk_score": v.risk_score,
        "description": v.description,
        "timestamp": v.timestamp,
        "line": v.line,
        "rule": v.rule,
        "status": v.status or "Open",
        "predictedSeverity": v.predicted_severity,
        "jenkins_job": v.jenkins_job,
        "build_number": v.build_number,
        "jenkins_url": v.jenkins_url,
        "traceability": {
            "jenkins_job": v.jenkins_job,
            "build_number": v.build_number,
            "jenkins_url": v.jenkins_url,
        },
    }
    
@app.post("/register_application")
def register_application(request: RegisterAppRequest, db: Session = Depends(get_db)):
    app_entry = db.query(Application).filter_by(name=request.name).first()
    if app_entry:
        return JSONResponse(status_code=400, content={"error": "Application already exists"})
    app_entry = Application(name=request.name, description=request.description, owner_email=request.owner_email, repo_url=request.repo_url, branch=request.branch)
    db.add(app_entry)
    db.commit()
    db.refresh(app_entry)
    return {"status": "registered", "application_id": app_entry.id}

@app.post("/grant_access")
def grant_access(request: GrantAccessRequest, db: Session = Depends(get_db)):
    app_entry = db.query(Application).filter_by(name=request.application).first()
    if not app_entry:
        return JSONResponse(status_code=404, content={"error": "Application not found"})
    access = ApplicationUserAccess(user_email=request.user_email, application_id=app_entry.id)
    db.add(access)
    db.commit()
    return {"status": "access granted"}

@app.post("/upload_vulnerabilities")
def upload_vulnerabilities(payload: UploadPayload, db: Session = Depends(get_db)):
    try:
        app_entry = db.query(Application).filter_by(name=payload.application).first()

        if not app_entry:
            app_entry = Application(
                name=payload.application,
                description="Auto-created",
                owner_email=payload.requestedBy or "unknown@horizonrelevance.com",
                repo_url=payload.repo_url or "N/A"
            )
            db.add(app_entry)
            db.commit()
            db.refresh(app_entry)
            print(f"[App Created] {payload.application}")

        count = 0
        for v in payload.vulnerabilities:
            vuln = Vulnerability(
                application_id=app_entry.id,
                target=v.target,
                package_name=v.package_name,
                installed_version=v.installed_version,
                vulnerability_id=v.vulnerability_id,
                severity=v.severity,
                fixed_version=v.fixed_version,
                risk_score=v.risk_score,
                description=v.description,
                source=v.source,
                timestamp=datetime.utcnow(),
                line=v.line,
                rule=v.rule,
                status=v.status,
                predicted_severity=v.predictedSeverity,
                jenkins_job=payload.jenkins_job,
                build_number=payload.build_number,
                jenkins_url=payload.jenkins_url
            )
            db.add(vuln)
            count += 1

        db.commit()
        print(f"[Vulnerabilities Uploaded] Count: {count} for app: {payload.application}")
        return {"status": "uploaded", "count": count}

    except Exception as e:
        print(f"[Upload Error] {str(e)}")
        return JSONResponse(status_code=500, content={"error": "Failed to upload vulnerabilities"})  

def verify_github_signature(payload_body: bytes, signature_header: str) -> bool:
    expected_signature = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(), msg=payload_body, digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    try:
        body = await request.body()

        if not x_hub_signature_256:
            return JSONResponse(status_code=401, content={"error": "Missing signature"})

        expected_signature = "sha256=" + hmac.new(
            GITHUB_WEBHOOK_SECRET.encode(),
            msg=body,
            digestmod=hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_signature, x_hub_signature_256):
            print(f"[Signature Mismatch] Expected: {expected_signature}")
            return JSONResponse(status_code=401, content={"error": "Invalid signature"})

        payload = json.loads(body)
        repo_url = payload.get("repository", {}).get("clone_url")
        branch_ref = payload.get("ref", "")
        branch = branch_ref.split("/")[-1] if branch_ref.startswith("refs/heads/") else "main"

        print(f"[Webhook] Repo: {repo_url}, Branch: {branch}")

        app_match = db.query(Application).filter(Application.repo_url == repo_url, Application.branch == branch).first()
        if not app_match:
            print(f"[Fallback] Trying to match repo only without branch: {repo_url}")
            app_match = db.query(Application).filter_by(repo_url=repo_url).first()
            if not app_match:
                return JSONResponse(status_code=404, content={"error": "No matching pipeline found for repo"})

        job_name = app_match.name
        jenkins_url = f"{JENKINS_URL}/job/{job_name}/buildWithParameters"
        params = {
            "REPO_URL": repo_url,
            "BRANCH": branch,
            "APP_TYPE": app_match.app_type or "unknown",
            "CREDENTIALS_ID": "github-token",
            "ENABLE_SONARQUBE": "true",
            "ENABLE_OPA": "true",
            "ENABLE_TRIVY": "true"
        }

        response = requests.post(jenkins_url, auth=(JENKINS_USER, JENKINS_TOKEN), params=params, verify=False)

        return {
            "status": "Triggered Jenkins job",
            "job": job_name,
            "jenkins_code": response.status_code
        }

    except Exception as e:
        print(f"[Webhook Error] {str(e)}")
        return JSONResponse(status_code=500, content={"error": "Failed to process webhook"})



# from fastapi import FastAPI, Request
# from fastapi import APIRouter, UploadFile
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.responses import JSONResponse
# from pydantic import BaseModel
# from typing import List, Optional
# import os
# import requests
# import json
# from ldap3 import Server, Connection, ALL, SUBTREE

# app = FastAPI(root_path="/pipeline/api")

# # Jenkins configuration
# JENKINS_URL = "https://horizonrelevance.com/jenkins"
# JENKINS_USER = os.getenv("JENKINS_USER")
# JENKINS_TOKEN = os.getenv("JENKINS_TOKEN")

# # LDAP configuration (JumpCloud)
# LDAP_SERVER = "ldaps://ldap.jumpcloud.com:636"
# LDAP_USER = "uid=ankur.kashyap,ou=Users,o=6817d9a0d50cd4b1b5b81ba7,dc=jumpcloud,dc=com"
# LDAP_PASSWORD = os.getenv("LDAP_MANAGER_PASSWORD")
# LDAP_BASE_DN = "ou=Users,o=6817d9a0d50cd4b1b5b81ba7,dc=jumpcloud,dc=com"
# SEARCH_FILTER = "(objectClass=person)"

# # CORS setup for frontend
# origins = ["https://horizonrelevance.com/pipeline"]

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# class PipelineRequest(BaseModel):
#     project_name: str
#     app_type: str
#     repo_url: str
#     branch: str
#     ENABLE_SONARQUBE: bool
#     ENABLE_OPA: bool
#     ENABLE_TRIVY: bool
#     requestedBy: str

# class TriggerRequest(BaseModel):
#     project_name: str

# class VulnerabilityModel(BaseModel):
#     target: str
#     package_name: str
#     installed_version: str
#     vulnerability_id: str
#     severity: str
#     fixed_version: Optional[str] = None
#     risk_score: float = 0.0
#     description: Optional[str] = None
#     source: Optional[str] = "Trivy"
#     timestamp: str = None
#     line: Optional[int] = None
#     rule: Optional[str] = None
#     status: Optional[str] = None
#     predictedSeverity: Optional[str] = None

# class VulnerabilityUpload(BaseModel):
#     vulnerabilities: List[VulnerabilityModel]    

# class OPARiskModel(BaseModel):
#     #source: str = "OPA"
#     target: str
#     violation: str
#     severity: str
#     risk_score: float

# class OPARiskUpload(BaseModel):
#     risks: List[OPARiskModel]        

# @app.post("/login")
# async def login(request: Request):
#     body = await request.json()
#     username = body.get("username")
#     password = body.get("password")

#     if not username or not password:
#         return JSONResponse(status_code=400, content={"error": "Username and password required"})

#     try:
#         server = Server(LDAP_SERVER, get_info=ALL)
#         search_conn = Connection(server, user=LDAP_USER, password=LDAP_PASSWORD, auto_bind=True)
#         search_conn.search(
#             search_base=LDAP_BASE_DN,
#             search_filter=f"(uid={username})",
#             search_scope=SUBTREE,
#             attributes=["displayName", "mail", "uid"]
#         )

#         if not search_conn.entries:
#             return JSONResponse(status_code=401, content={"error": "User not found"})

#         user_entry = search_conn.entries[0]
#         user_dn = str(user_entry.entry_dn)
#         display_name = str(user_entry.displayName)
#         email = str(user_entry.mail)
#         search_conn.unbind()

#         auth_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
#         auth_conn.unbind()

#         return {
#             "username": username,
#             "fullName": display_name,
#             "email": email
#         }

#     except Exception as e:
#         import traceback
#         traceback.print_exc()
#         return JSONResponse(status_code=401, content={"error": "Invalid credentials or server error"})

# @app.get("/get_ldap_users")
# def get_ldap_users():
#     try:
#         server = Server(LDAP_SERVER, get_info=ALL)
#         conn = Connection(server, user=LDAP_USER, password=LDAP_PASSWORD, auto_bind=True)

#         conn.search(
#             search_base=LDAP_BASE_DN,
#             search_filter=SEARCH_FILTER,
#             search_scope=SUBTREE,
#             attributes=["uid", "displayName", "mail"]
#         )

#         users = []
#         seen = set()

#         for entry in conn.entries:
#             uid = str(entry.uid) if "uid" in entry else None
#             display_name = str(entry.displayName) if "displayName" in entry else uid
#             email = str(entry.mail) if "mail" in entry else ""

#             if uid and uid not in seen:
#                 users.append({
#                     "username": uid,
#                     "fullName": display_name,
#                     "email": email
#                 })
#                 seen.add(uid)

#         conn.unbind()
#         return JSONResponse(content=users)

#     except Exception as e:
#         print("LDAP error:", e)
#         return JSONResponse(status_code=500, content={"error": "Failed to fetch LDAP users"})

# @app.post("/pipeline")
# def create_pipeline(request: PipelineRequest):
#     print("Received pipeline request:", request.dict())

#     # Use Jenkins job parameters instead of hardcoding in the script
#     job_config = f"""
#     <flow-definition plugin="workflow-job">
#       <actions/>
#       <description>Dynamic Jenkins Pipeline for {request.project_name}</description>
#       <keepDependencies>false</keepDependencies>
#       <properties/>
#       <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
#         <script>
#           @Library('jenkins-shared-library@main') _
#           main_template(
#             APP_TYPE: params.APP_TYPE,
#             REPO_URL: params.REPO_URL,
#             BRANCH: params.BRANCH,
#             CREDENTIALS_ID: params.CREDENTIALS_ID,
#             ENABLE_SONARQUBE: params.ENABLE_SONARQUBE,
#             ENABLE_OPA: params.ENABLE_OPA,
#             ENABLE_TRIVY: params.ENABLE_TRIVY
#           )
#         </script>
#         <sandbox>true</sandbox>
#       </definition>
#       <triggers/>
#       <disabled>false</disabled>
#     </flow-definition>
#     """

#     # Define job parameters separately
#     params_payload = {
#         "name": request.project_name,
#         "parameters": [
#             {"name": "APP_TYPE", "value": request.app_type},
#             {"name": "REPO_URL", "value": request.repo_url},
#             {"name": "BRANCH", "value": request.branch},
#             {"name": "CREDENTIALS_ID", "value": "github-token"},
#             {"name": "ENABLE_SONARQUBE", "value": str(request.ENABLE_SONARQUBE).lower()},
#             {"name": "ENABLE_OPA", "value": str(request.ENABLE_OPA).lower()},
#             {"name": "ENABLE_TRIVY", "value": str(request.ENABLE_TRIVY).lower()}
#         ]
#     }

#     # Create job
#     create_response = requests.post(
#         f"{JENKINS_URL}/createItem?name={request.project_name}",
#         headers={"Content-Type": "application/xml"},
#         auth=(JENKINS_USER, JENKINS_TOKEN),
#         data=job_config,
#         verify=False
#     )
#     print("Jenkins Create Response:", create_response.status_code, create_response.text)

#     # Trigger build with parameters
#     build_response = requests.post(
#         f"{JENKINS_URL}/job/{request.project_name}/buildWithParameters",
#         auth=(JENKINS_USER, JENKINS_TOKEN),
#         params={p["name"]: p["value"] for p in params_payload["parameters"]},
#         verify=False
#     )
#     print("Jenkins Build Trigger Response:", build_response.status_code, build_response.text)

#     return {
#         "status": "Pipeline created and triggered",
#         "create_response_code": create_response.status_code,
#         "build_response_code": build_response.status_code
#     }

# # @app.post("/pipeline")
# # def create_pipeline(request: PipelineRequest):
# #     print("Received pipeline request:", request.dict())

# #     jenkinsfile_template = f"""
# #     @Library('jenkins-shared-library@main') _
# #     pipeline {{
# #         agent any
# #         stages {{
# #             stage('Clone Repository') {{
# #                 steps {{
# #                     git credentialsId: 'github-token', url: '{request.repo_url}', branch: '{request.branch}'
# #                 }}
# #             }}
# #             stage('Print Incoming Parameters') {{
# #                 steps {{
# #                     script {{
# #                         echo "==== Incoming Parameters ===="
# #                         params.each {{ key, value -> 
# #                             echo "${{key}} = ${{value}}"
# #                         }}
# #                         echo "=============================="
# #                     }}
# #                 }}
# #             }}
# #             stage('Check Repository') {{
# #                 steps {{
# #                     script {{
# #                         sh 'pwd'
# #                         sh 'ls -lrth'
# #                     }}
# #                 }}
# #             }}
# #             stage('Load Application Pipeline') {{
# #                 steps {{
# #                     script {{
# #                         main_template(APP_TYPE: '{request.app_type}', 
# #                                       REPO_URL: '{request.repo_url}', 
# #                                       BRANCH: '{request.branch}', 
# #                                       CREDENTIALS_ID: 'github-token', 
# #                                       ENABLE_SONARQUBE: {str(request.ENABLE_SONARQUBE).lower()}, 
# #                                       ENABLE_OPA: {str(request.ENABLE_OPA).lower()},
# #                                       ENABLE_TRIVY: {str(request.ENABLE_TRIVY).lower()})
# #                     }}
# #                 }}
# #             }}
# #         }}
# #     }}
# #     """

# #     job_config = f"""
# #     <flow-definition plugin="workflow-job">
# #         <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
# #             <script>{jenkinsfile_template}</script>
# #             <sandbox>true</sandbox>
# #         </definition>
# #     </flow-definition>
# #     """

# #     create_response = requests.post(
# #         f"{JENKINS_URL}/createItem?name={request.project_name}",
# #         headers={"Content-Type": "application/xml"},
# #         auth=(JENKINS_USER, JENKINS_TOKEN),
# #         data=job_config,
# #         verify=False
# #     )
# #     print("Jenkins Create Response:", create_response.status_code, create_response.text)

# #     if create_response.status_code not in [200, 201]:
# #         return {
# #             "status": "Failed to create pipeline",
# #             "create_response_code": create_response.status_code,
# #             "jenkins_response": create_response.text
# #         }

# #     build_response = requests.post(
# #         f"{JENKINS_URL}/job/{request.project_name}/build",
# #         auth=(JENKINS_USER, JENKINS_TOKEN),
# #         verify=False
# #     )
# #     print("Jenkins Build Trigger Response:", build_response.status_code, build_response.text)

# #     return {
# #         "status": "Pipeline created and triggered",
# #         "create_response_code": create_response.status_code,
# #         "build_response_code": build_response.status_code
# #     }

# @app.post("/pipeline/trigger")
# def trigger_existing_pipeline(request: TriggerRequest):
#     job_url = f"{JENKINS_URL}/job/{request.project_name}/api/json"
#     job_check = requests.get(job_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)

#     if job_check.status_code != 200:
#         return {
#             "status": "Job not found",
#             "message": f"Pipeline '{request.project_name}' does not exist.",
#             "code": job_check.status_code
#         }

#     build_url = f"{JENKINS_URL}/job/{request.project_name}/build"
#     build_trigger = requests.post(build_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)

#     if build_trigger.status_code in [200, 201]:
#         return {
#             "status": "Build triggered",
#             "project_name": request.project_name,
#             "trigger_response_code": build_trigger.status_code
#         }
#     else:
#         return {
#             "status": "Failed to trigger build",
#             "response_code": build_trigger.status_code,
#             "jenkins_response": build_trigger.text
#         }

# @app.get("/pipeline/logs/{job_name}/{build_number}")
# def get_console_logs(job_name: str, build_number: int):
#     log_url = f"{JENKINS_URL}/job/{job_name}/{build_number}/logText/progressiveText"
#     response = requests.get(log_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
#     return {
#         "build_number": build_number,
#         "job_name": job_name,
#         "logs": response.text
#     }

# # Global store for vulnerabilities (temporary until DB is added)
# vulnerabilities_store = []
# # Add this new POST API
# @app.post("/vulnerabilities")
# async def upload_vulnerabilities(payload: VulnerabilityUpload):
#     try:
#         # (Optional) Save to DB here if needed
        
#         # For now, just print the vulnerabilities for debugging
#         for vuln in payload.vulnerabilities:
#             try:
#             # Add timestamp dynamically if not already provided
#                 if not vuln.timestamp:
#                     from datetime import datetime
#                     vuln.timestamp = datetime.utcnow().isoformat()

#                 print(f"Received vulnerability: {vuln}")
#                 vulnerabilities_store.append(vuln.dict())  # Save into in-memory store
#             except Exception as e:
#                 print(f"Failed to process a vulnerability: {e}")    
#         return {"status": "success", "received_count": len(payload.vulnerabilities)}
    
#     except Exception as e:
#         print(f"Error processing vulnerabilities: {e}")
#         return JSONResponse(status_code=500, content={"error": "Failed to process vulnerabilities"}) 
    
# # ⬇️ ADD THIS GET FUNCTION ⬇️
# @app.get("/vulnerabilities")
# async def get_vulnerabilities(source: Optional[str] = None):
#     if source:
#         return [v for v in vulnerabilities_store if v.get("source") == source]
#     return vulnerabilities_store   

# @app.delete("/vulnerabilities/clear")
# def clear_vulnerabilities():
#     global vulnerabilities_store
#     vulnerabilities_store = []
#     return {"status": "cleared"}

# @app.post("/opa/risks/")
# async def upload_opa_risks(payload: OPARiskUpload):
#     try:
#         for risk in payload.risks:
#             print(f"Received OPA Risk: {risk}")
#             vuln_dict = {
#                 "target": risk.target,
#                 "package_name": "OPA Policy",
#                 "installed_version": "N/A",
#                 "vulnerability_id": risk.violation,
#                 "severity": risk.severity,
#                 "fixed_version": get_dynamic_fix(risk.violation),
#                 "risk_score": risk.risk_score,
#                 "description": get_dynamic_fix(risk.violation),
#                 "source": "OPA"
#             }
#             vulnerabilities_store.append(vuln_dict)
#         return {"status": "success", "received_count": len(payload.risks)}
#     except Exception as e:
#         print(f"Error processing OPA risks: {e}")
#         return JSONResponse(status_code=500, content={"error": "Failed to process OPA risks"})

# def get_dynamic_fix(violation: str) -> str:
#     violation = violation.lower()
#     if "root user" in violation:
#         return "Use a non-root USER in Dockerfile"
#     elif "ssh port" in violation:
#         return "Avoid exposing port 22 unless explicitly needed"
#     elif "privileged" in violation:
#         return "Set privileged: false in your container configuration"
#     elif "capabilities" in violation:
#         return "Drop all Linux capabilities and add only required ones"
#     elif "no read-only" in violation or "writable" in violation:
#         return "Set filesystem to read-only using readOnlyRootFilesystem"
#     else:
#         return "Review OPA policy and secure container accordingly"
