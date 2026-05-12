from fastapi import FastAPI, Request, Depends, Header, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import os
import requests
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.utils.conv import escape_filter_chars
import logging
import json
import hmac
import hashlib
import re
from html import escape

from database import SessionLocal, engine, Base
from models import Application, ApplicationUserAccess, Vulnerability, EnvironmentCatalog
from enterprise.licensing import (
    LicenseValidationError,
    default_license_from_env,
    license_summary,
    merge_request_license,
    save_cached_license,
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

def jenkins_headers(content_type: Optional[str] = None):
    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    try:
        crumb_response = requests.get(
            f"{JENKINS_URL}/crumbIssuer/api/json",
            auth=(JENKINS_USER, JENKINS_TOKEN),
            verify=False,
            timeout=10,
        )
        if crumb_response.status_code == 200:
            crumb = crumb_response.json()
            headers[crumb["crumbRequestField"]] = crumb["crumb"]
    except Exception as exc:
        logger.warning("Unable to fetch Jenkins crumb: %s", exc)
    return headers

def jenkins_post(url: str, content_type: Optional[str] = None, data=None, params=None):
    session = requests.Session()
    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    try:
        crumb_response = session.get(
            f"{JENKINS_URL}/crumbIssuer/api/json",
            auth=(JENKINS_USER, JENKINS_TOKEN),
            verify=False,
            timeout=10,
        )
        if crumb_response.status_code == 200:
            crumb = crumb_response.json()
            headers[crumb["crumbRequestField"]] = crumb["crumb"]
    except Exception as exc:
        logger.warning("Unable to fetch Jenkins crumb for POST: %s", exc)
    return session.post(
        url,
        headers=headers,
        auth=(JENKINS_USER, JENKINS_TOKEN),
        data=data,
        params=params,
        verify=False,
    )

# GitHub webhook secret
GITHUB_WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]

def aws_account_id_from_registry(registry: Optional[str]) -> Optional[str]:
    if not registry:
        return None
    registry_value = registry.strip()
    if re.fullmatch(r"[0-9]{12}", registry_value):
        return registry_value
    match = re.search(r"([0-9]{12})\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com", registry_value)
    return match.group(1) if match else None

# LDAP configuration
LDAP_SERVER = os.getenv("LDAP_SERVER", "ldap://openldap.horizon-relevance-dev.svc.cluster.local:389")
LDAP_USER = os.getenv("LDAP_USER", "cn=admin,dc=horizonrelevance,dc=local")
LDAP_PASSWORD = os.getenv("LDAP_MANAGER_PASSWORD")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "ou=users,dc=horizonrelevance,dc=local")
SEARCH_FILTER = os.getenv("LDAP_SEARCH_FILTER", "(objectClass=inetOrgPerson)")
LDAP_UID_ATTRIBUTE = os.getenv("LDAP_UID_ATTRIBUTE", "uid")
LDAP_DISPLAY_NAME_ATTRIBUTE = os.getenv("LDAP_DISPLAY_NAME_ATTRIBUTE", "displayName")
LDAP_MAIL_ATTRIBUTE = os.getenv("LDAP_MAIL_ATTRIBUTE", "mail")
LDAP_GROUP_BASE_DN = os.getenv("LDAP_GROUP_BASE_DN", "ou=groups,dc=horizonrelevance,dc=local")
LDAP_GROUP_SEARCH_FILTER = os.getenv("LDAP_GROUP_SEARCH_FILTER", "(objectClass=groupOfNames)")
LDAP_GROUP_MEMBER_ATTRIBUTE = os.getenv("LDAP_GROUP_MEMBER_ATTRIBUTE", "member")
LDAP_GROUP_NAME_ATTRIBUTE = os.getenv("LDAP_GROUP_NAME_ATTRIBUTE", "cn")
LDAP_USER_GROUP_ATTRIBUTE = os.getenv("LDAP_USER_GROUP_ATTRIBUTE", "memberOf")
LDAP_ROLE_GROUP_MAPPINGS_RAW = os.getenv("LDAP_ROLE_GROUP_MAPPINGS", "{}")
ENVIRONMENT_CATALOG_FILE = os.getenv("ENVIRONMENT_CATALOG_FILE", "/app/config/environment-catalog.json")

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
    allowed_aws_account_ids: Optional[List[str]] = None
    installation_id: Optional[str] = None
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
    ENABLE_RESTASSURED: bool = False
    ENABLE_UFT: bool = False
    ENABLE_TRIVY: bool = False
    target_env: str = "DEV"
    notify_email: Optional[str] = None
    additional_notify_emails: Optional[str] = None
    aws_region: Optional[str] = None
    ecr_registry: Optional[str] = None
    ecr_repository: Optional[str] = None
    artifact_bucket: Optional[str] = None
    client_aws_role_arn: Optional[str] = None
    nonprod_aws_role_arn: Optional[str] = None
    target_aws_role_arn: Optional[str] = None
    dev_cluster_name: Optional[str] = None
    qa_cluster_name: Optional[str] = None
    stage_cluster_name: Optional[str] = None
    prod_cluster_name: Optional[str] = None
    namespace_strategy: str = "auto"
    app_namespace: Optional[str] = None
    dev_namespace: Optional[str] = None
    qa_namespace: Optional[str] = None
    stage_namespace: Optional[str] = None
    prod_namespace: Optional[str] = None
    enable_notifications: bool = False
    sns_topic_arn: Optional[str] = None

class TestDevopsPipelineRequest(BaseModel):
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
    allowed_aws_account_ids: Optional[List[str]] = None
    installation_id: Optional[str] = None
    project_name: str
    project_type: str
    repo_type: str = "GitHub"
    repo_url: str
    branch: str = "main"
    ENABLE_SONARQUBE: bool = False
    ENABLE_CHECKMARX: bool = False
    checkmarx_team: Optional[str] = None
    ENABLE_SOAPUI: bool = False
    ENABLE_JMETER: bool = False
    ENABLE_SELENIUM: bool = False
    ENABLE_NEWMAN: bool = False
    ENABLE_RESTASSURED: bool = False
    ENABLE_UFT: bool = False
    ENABLE_TRIVY: bool = False
    ENABLE_OPA: bool = False
    image_uri: Optional[str] = None
    target_app_url: Optional[str] = None
    api_base_url: Optional[str] = None
    jmeter_test_plan: Optional[str] = None
    jmeter_threads: Optional[str] = "10"
    jmeter_ramp_seconds: Optional[str] = "30"
    jmeter_loops: Optional[str] = "5"
    jmeter_max_error_percent: Optional[str] = "1"
    jmeter_max_avg_ms: Optional[str] = "2000"
    jmeter_max_p95_ms: Optional[str] = "5000"
    newman_collection_path: Optional[str] = None
    newman_environment_path: Optional[str] = None
    newman_data_file: Optional[str] = None
    newman_timeout_ms: Optional[str] = "30000"
    newman_fail_on_error: bool = True
    target_env: str = "QA"
    notify_email: Optional[str] = None
    additional_notify_emails: Optional[str] = None
    aws_region: str = "us-east-1"
    artifact_bucket: Optional[str] = None
    client_aws_role_arn: Optional[str] = None
    nonprod_aws_role_arn: Optional[str] = None
    target_aws_role_arn: Optional[str] = None
    enable_notifications: bool = False
    sns_topic_arn: Optional[str] = None

class ProdDevopsPipelineRequest(BaseModel):
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
    allowed_aws_account_ids: Optional[List[str]] = None
    installation_id: Optional[str] = None
    project_name: str
    artifact_bucket: Optional[str] = None
    artifact_prefix: str
    image_json_path: Optional[str] = None
    template_config_path: Optional[str] = None
    source_env: str = "STAGE"
    target_env: str = "PROD"
    aws_region: str = "us-east-1"
    source_ecr_registry: Optional[str] = None
    source_ecr_repository: Optional[str] = None
    target_ecr_registry: Optional[str] = None
    target_ecr_repository: Optional[str] = None
    source_image_tag: Optional[str] = None
    target_image_tag: str = "prod"
    client_aws_role_arn: Optional[str] = None
    source_aws_role_arn: Optional[str] = None
    target_aws_role_arn: Optional[str] = None
    dev_cluster_name: Optional[str] = None
    qa_cluster_name: Optional[str] = None
    stage_cluster_name: Optional[str] = None
    prod_cluster_name: Optional[str] = None
    namespace_strategy: str = "auto"
    app_namespace: Optional[str] = None
    dev_namespace: Optional[str] = None
    qa_namespace: Optional[str] = None
    stage_namespace: Optional[str] = None
    prod_namespace: Optional[str] = None
    secret_enabled: bool = False
    xid_array: Optional[str] = None
    approver: Optional[str] = None
    notify_email: Optional[str] = None
    additional_notify_emails: Optional[str] = None
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
    allowed_aws_account_ids: Optional[List[str]] = None
    installation_id: Optional[str] = None
    pipeline_name: str = "Devops Pipeline"
    target_env: str = "EKS-NONPROD"
    requested_features: List[str] = []

class LicenseSyncRequest(BaseModel):
    force: Optional[bool] = False

class EnvironmentCatalogEntryRequest(BaseModel):
    name: str
    display_name: Optional[str] = None
    account_tier: Optional[str] = None
    aws_account_id: Optional[str] = None
    aws_region: Optional[str] = "us-east-1"
    ecr_registry: Optional[str] = None
    ecr_repository_template: Optional[str] = None
    artifact_bucket: Optional[str] = None
    client_aws_role_arn: Optional[str] = None
    nonprod_aws_role_arn: Optional[str] = None
    source_aws_role_arn: Optional[str] = None
    target_aws_role_arn: Optional[str] = None
    cluster_name: Optional[str] = None
    namespace_strategy: Optional[str] = "auto"
    namespace_template: Optional[str] = "{client_id}-{project_name}-{env}"
    sns_topic_arn: Optional[str] = None
    is_active: bool = True

class EnvironmentCatalogRequest(BaseModel):
    environments: List[EnvironmentCatalogEntryRequest]

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
    source: Optional[str] = "Security Finding"
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
    source: Optional[str] = "Policy Violation"    
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

def requested_test_devops_features(request: TestDevopsPipelineRequest) -> List[str]:
    features = []
    if request.ENABLE_SONARQUBE:
        features.append("code_scan")
    if request.ENABLE_TRIVY:
        features.append("image_scan")
    if request.ENABLE_OPA:
        features.append("policy_scan")
    if request.ENABLE_CHECKMARX:
        features.append("static_application_security")
    if request.ENABLE_JMETER or request.ENABLE_SELENIUM or request.ENABLE_NEWMAN:
        features.append("test_suites")
    if request.enable_notifications:
        features.append("notifications")
    return features

def requested_prod_devops_features(request: ProdDevopsPipelineRequest) -> List[str]:
    features = ["artifact_publish", "prod_deploy"]
    if request.secret_enabled:
        features.append("secret_management")
    if request.enable_notifications:
        features.append("notifications")
    return features

ENVIRONMENT_ALIASES = {
    "EKS-NONPROD": "DEV",
    "EKS-PROD": "PROD",
}

def parse_ldap_role_group_mappings(raw: str) -> Dict[str, set]:
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("Invalid LDAP_ROLE_GROUP_MAPPINGS JSON: %s", exc)
        return {}

    normalized = {}
    if isinstance(payload, dict):
        iterable = payload.items()
    elif isinstance(payload, list):
        iterable = ((item.get("role"), item.get("groups")) for item in payload if isinstance(item, dict))
    else:
        return {}

    for role, groups in iterable:
        role_name = str(role or "").strip()
        if not role_name:
            continue
        if isinstance(groups, str):
            groups = [groups]
        if not isinstance(groups, list):
            continue
        normalized[role_name] = {str(group).strip().lower() for group in groups if str(group).strip()}
    return normalized


LDAP_ROLE_GROUP_MAPPINGS = parse_ldap_role_group_mappings(LDAP_ROLE_GROUP_MAPPINGS_RAW)


def cn_from_dn(dn: str) -> Optional[str]:
    match = re.search(r"(?i)(?:^|,)\s*cn=([^,]+)", dn or "")
    return match.group(1).replace("\\,", ",").strip() if match else None


def ldap_entry_values(entry, attribute: str) -> List[str]:
    if not attribute or attribute not in entry:
        return []
    value = entry[attribute]
    if hasattr(value, "values"):
        return [str(item) for item in value.values]
    return [str(value)]


def resolve_ldap_groups(search_conn: Connection, user_entry, user_dn: str) -> List[str]:
    groups = set()

    for member_group in ldap_entry_values(user_entry, LDAP_USER_GROUP_ATTRIBUTE):
        groups.add(member_group)
        group_cn = cn_from_dn(member_group)
        if group_cn:
            groups.add(group_cn)

    try:
        search_conn.search(
            search_base=LDAP_GROUP_BASE_DN,
            search_filter=f"(&{LDAP_GROUP_SEARCH_FILTER}({LDAP_GROUP_MEMBER_ATTRIBUTE}={escape_filter_chars(user_dn)}))",
            search_scope=SUBTREE,
            attributes=[LDAP_GROUP_NAME_ATTRIBUTE],
        )
        for entry in search_conn.entries:
            groups.add(str(entry.entry_dn))
            for group_name in ldap_entry_values(entry, LDAP_GROUP_NAME_ATTRIBUTE):
                groups.add(group_name)
    except Exception as group_exc:
        logger.warning("Unable to resolve LDAP groups for %s: %s", user_dn, group_exc)

    return sorted(groups)


def resolve_roles_from_ldap_groups(groups: List[str]) -> List[str]:
    normalized_groups = {str(group).strip().lower() for group in groups if str(group).strip()}
    roles = sorted([
        role for role, allowed_groups in LDAP_ROLE_GROUP_MAPPINGS.items()
        if normalized_groups.intersection(allowed_groups)
    ])
    return roles or ["viewer"]


def normalize_environment_name(value: Optional[str]) -> str:
    env = (value or "DEV").strip().upper()
    return ENVIRONMENT_ALIASES.get(env, env)


def slugify_value(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._/-]+", "-", (value or "").strip()).strip("-._/")
    return (slug or "application").lower()


def render_catalog_template(value: Optional[str], project_name: str, client_id: str, env: str) -> str:
    if not value:
        return ""
    project_slug = slugify_value(project_name)
    client_slug = slugify_value(client_id or "client")
    return (
        value.replace("{project_name}", project_slug)
        .replace("{client_id}", client_slug)
        .replace("{env}", env.lower())
        .replace("{ENV}", env.upper())
    )


def catalog_entry_to_dict(entry: EnvironmentCatalog) -> Dict[str, Any]:
    return {
        "name": entry.name,
        "display_name": entry.display_name or entry.name,
        "account_tier": entry.account_tier or "nonprod",
        "aws_account_id": entry.aws_account_id or "",
        "aws_region": entry.aws_region or "us-east-1",
        "ecr_registry": entry.ecr_registry or "",
        "ecr_repository_template": entry.ecr_repository_template or "{project_name}",
        "artifact_bucket": entry.artifact_bucket or "",
        "client_aws_role_arn": entry.client_aws_role_arn or "",
        "nonprod_aws_role_arn": entry.nonprod_aws_role_arn or "",
        "source_aws_role_arn": entry.source_aws_role_arn or "",
        "target_aws_role_arn": entry.target_aws_role_arn or "",
        "cluster_name": entry.cluster_name or "",
        "namespace_strategy": entry.namespace_strategy or "auto",
        "namespace_template": entry.namespace_template or "{client_id}-{project_name}-{env}",
        "sns_topic_arn": entry.sns_topic_arn or "",
        "is_active": bool(entry.is_active),
        "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
    }


def load_environment_catalog_seed() -> List[Dict[str, Any]]:
    if ENVIRONMENT_CATALOG_FILE and os.path.exists(ENVIRONMENT_CATALOG_FILE):
        with open(ENVIRONMENT_CATALOG_FILE, "r", encoding="utf-8") as catalog_file:
            payload = json.load(catalog_file)
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            return payload.get("environments") or []
    return [
        {"name": "DEV", "display_name": "Development", "account_tier": "nonprod"},
        {"name": "QA", "display_name": "Quality Assurance", "account_tier": "nonprod"},
        {"name": "STAGE", "display_name": "Stage", "account_tier": "nonprod"},
        {"name": "PROD", "display_name": "Production", "account_tier": "prod"},
    ]


def upsert_environment_catalog_entry(db: Session, raw: Dict[str, Any]) -> EnvironmentCatalog:
    env_name = normalize_environment_name(raw.get("name"))
    entry = db.query(EnvironmentCatalog).filter(EnvironmentCatalog.name == env_name).first()
    if not entry:
        entry = EnvironmentCatalog(name=env_name)
        db.add(entry)
    allowed_fields = [
        "display_name", "account_tier", "aws_account_id", "aws_region", "ecr_registry",
        "ecr_repository_template", "artifact_bucket", "client_aws_role_arn", "nonprod_aws_role_arn",
        "source_aws_role_arn", "target_aws_role_arn", "cluster_name", "namespace_strategy",
        "namespace_template", "sns_topic_arn",
    ]
    for field in allowed_fields:
        value = raw.get(field)
        if value is not None:
            setattr(entry, field, str(value).strip())
    entry.is_active = 1 if raw.get("is_active", True) else 0
    entry.updated_at = datetime.utcnow()
    return entry


def ensure_environment_catalog_seeded(db: Session) -> None:
    if db.query(EnvironmentCatalog).count() > 0:
        return
    for raw in load_environment_catalog_seed():
        upsert_environment_catalog_entry(db, raw)
    db.commit()


def resolve_environment_catalog_values(db: Session, target_env: str, project_name: str, request: Optional[BaseModel] = None):
    env = normalize_environment_name(target_env)
    ensure_environment_catalog_seeded(db)
    entry = db.query(EnvironmentCatalog).filter(EnvironmentCatalog.name == env, EnvironmentCatalog.is_active == 1).first()
    if not entry:
        return None, f"Environment catalog entry '{env}' is not configured or inactive. Ask a platform admin to configure Environment Catalog."

    catalog = catalog_entry_to_dict(entry)
    request_values = request.dict() if request else {}

    def request_value(name: str) -> str:
        value = request_values.get(name)
        return str(value).strip() if value is not None else ""

    def resolved(name: str, fallback: str = "") -> str:
        catalog_value = str(catalog.get(name) or "").strip()
        return catalog_value or request_value(name) or fallback

    license_doc = merge_request_license(request_values)
    client_id = str(license_doc.get("client_id") or request_value("client_id") or "client").strip()
    repository_template = resolved("ecr_repository_template", "{project_name}")
    namespace_template = resolved("namespace_template", "{client_id}-{project_name}-{env}")
    namespace_strategy = resolved("namespace_strategy", request_value("namespace_strategy") or "auto")
    manual_namespace = request_value("app_namespace")
    namespace = manual_namespace if namespace_strategy == "manual" and manual_namespace else render_catalog_template(namespace_template, project_name, client_id, env)
    cluster_name = resolved("cluster_name", request_value(f"{env.lower()}_cluster_name"))
    client_role = resolved("client_aws_role_arn")
    nonprod_role = resolved("nonprod_aws_role_arn", client_role)
    source_role = resolved("source_aws_role_arn", nonprod_role or client_role)
    target_role = resolved("target_aws_role_arn", nonprod_role or client_role)
    ecr_registry = resolved("ecr_registry", resolved("aws_account_id"))

    clusters = {"DEV": "", "QA": "", "STAGE": "", "PROD": ""}
    namespaces = {"DEV": "", "QA": "", "STAGE": "", "PROD": ""}
    if env in clusters:
        clusters[env] = cluster_name
        namespaces[env] = namespace

    return {
        "TARGET_ENV": env,
        "AWS_REGION": resolved("aws_region", "us-east-1"),
        "AWS_ACCOUNT_ID": resolved("aws_account_id", aws_account_id_from_registry(ecr_registry) or ""),
        "ECR_REGISTRY": ecr_registry,
        "ECR_REPOSITORY": render_catalog_template(repository_template, project_name, client_id, env),
        "ARTIFACT_BUCKET": resolved("artifact_bucket"),
        "CLIENT_AWS_ROLE_ARN": client_role,
        "NONPROD_AWS_ROLE_ARN": nonprod_role,
        "SOURCE_AWS_ROLE_ARN": source_role,
        "TARGET_AWS_ROLE_ARN": target_role,
        "DEV_CLUSTER_NAME": clusters["DEV"] or request_value("dev_cluster_name"),
        "QA_CLUSTER_NAME": clusters["QA"] or request_value("qa_cluster_name"),
        "STAGE_CLUSTER_NAME": clusters["STAGE"] or request_value("stage_cluster_name"),
        "PROD_CLUSTER_NAME": clusters["PROD"] or request_value("prod_cluster_name"),
        "NAMESPACE_STRATEGY": namespace_strategy,
        "APP_NAMESPACE": namespace,
        "DEV_NAMESPACE": namespaces["DEV"] or request_value("dev_namespace"),
        "QA_NAMESPACE": namespaces["QA"] or request_value("qa_namespace"),
        "STAGE_NAMESPACE": namespaces["STAGE"] or request_value("stage_namespace"),
        "PROD_NAMESPACE": namespaces["PROD"] or request_value("prod_namespace"),
        "SNS_TOPIC_ARN": resolved("sns_topic_arn", request_value("sns_topic_arn")),
        "catalog": catalog,
    }, None


@app.get("/environment-catalog")
def get_environment_catalog(db: Session = Depends(get_db)):
    ensure_environment_catalog_seeded(db)
    entries = db.query(EnvironmentCatalog).order_by(EnvironmentCatalog.name.asc()).all()
    return {"environments": [catalog_entry_to_dict(entry) for entry in entries]}


@app.get("/environment-catalog/resolve/{target_env}")
def resolve_environment_catalog(target_env: str, project_name: str = "application", db: Session = Depends(get_db)):
    resolved, error = resolve_environment_catalog_values(db, target_env, project_name)
    if error:
        return JSONResponse(status_code=404, content={"error": error})
    return resolved


@app.post("/environment-catalog")
def save_environment_catalog(request: EnvironmentCatalogRequest, db: Session = Depends(get_db)):
    if not request.environments:
        return JSONResponse(status_code=400, content={"error": "At least one environment is required"})
    for environment in request.environments:
        upsert_environment_catalog_entry(db, environment.dict())
    db.commit()
    entries = db.query(EnvironmentCatalog).order_by(EnvironmentCatalog.name.asc()).all()
    return {"status": "saved", "environments": [catalog_entry_to_dict(entry) for entry in entries]}

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

@app.post("/license/sync")
def sync_enterprise_license(request: LicenseSyncRequest):
    license_mode = os.getenv("ENTERPRISE_LICENSE_MODE", "offline-file").strip().lower()
    sync_endpoint = os.getenv("ENTERPRISE_LICENSE_SYNC_ENDPOINT", "").strip()
    activation_token = os.getenv("ENTERPRISE_LICENSE_ACTIVATION_TOKEN", "").strip()
    current_license = default_license_from_env()

    if license_mode != "online-sync":
        return JSONResponse(
            status_code=400,
            content={
                "error": "Online license sync is not enabled for this deployment.",
                "status": "sync_disabled",
                "license_mode": license_mode,
            },
        )
    if not sync_endpoint:
        return JSONResponse(status_code=400, content={"error": "ENTERPRISE_LICENSE_SYNC_ENDPOINT is required.", "status": "sync_failed"})
    if not activation_token:
        return JSONResponse(status_code=400, content={"error": "ENTERPRISE_LICENSE_ACTIVATION_TOKEN is required.", "status": "sync_failed"})

    payload = {
        "client_id": current_license.get("client_id") or os.getenv("ENTERPRISE_CLIENT_ID", ""),
        "client_name": current_license.get("client_name") or os.getenv("ENTERPRISE_CLIENT_NAME", ""),
        "activation_token": activation_token,
        "current_license_key": current_license.get("license_key", ""),
        "current_expires_at": current_license.get("expires_at", ""),
        "force": bool(request.force),
        "platform": {
            "product": "Horizon Relevance AI DevSecOps Platform",
            "backend_root_path": "/pipeline/api",
            "license_mode": license_mode,
        },
    }

    try:
        response = requests.post(sync_endpoint, json=payload, timeout=15)
    except requests.RequestException as exc:
        logger.exception("License sync failed while calling Horizon license service")
        return JSONResponse(status_code=502, content={"error": f"License service unreachable: {exc}", "status": "sync_failed"})

    if response.status_code >= 400:
        try:
            error_body = response.json()
        except ValueError:
            error_body = {"error": response.text}
        error_body.setdefault("status", "sync_failed")
        return JSONResponse(status_code=response.status_code, content=error_body)

    try:
        response_body = response.json()
    except ValueError:
        return JSONResponse(status_code=502, content={"error": "License service returned non-JSON response.", "status": "sync_failed"})

    synced_license = response_body.get("license") or response_body
    synced_license["license_mode"] = "online-sync"

    try:
        validated = validate_license(
            synced_license,
            pipeline_name="Devops Pipeline",
            target_env=(synced_license.get("allowed_environments") or ["DEV"])[0],
            requested_features=[],
        )
    except LicenseValidationError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc), "status": "sync_invalid"})

    cached = save_cached_license(validated)
    summary = license_summary(cached)
    summary["status"] = "active"
    summary["message"] = response_body.get("message", "License synced successfully.")
    return summary

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
            search_filter=f"({LDAP_UID_ATTRIBUTE}={escape_filter_chars(username)})",
            search_scope=SUBTREE,
            attributes=[LDAP_DISPLAY_NAME_ATTRIBUTE, LDAP_MAIL_ATTRIBUTE, LDAP_UID_ATTRIBUTE]
        )
        if not search_conn.entries:
            search_conn.unbind()
            return JSONResponse(status_code=401, content={"error": "User not found"})

        user_entry = search_conn.entries[0]
        user_dn = str(user_entry.entry_dn)
        display_name = str(user_entry[LDAP_DISPLAY_NAME_ATTRIBUTE]) if LDAP_DISPLAY_NAME_ATTRIBUTE in user_entry else username
        email = str(user_entry[LDAP_MAIL_ATTRIBUTE]) if LDAP_MAIL_ATTRIBUTE in user_entry else ""
        groups = resolve_ldap_groups(search_conn, user_entry, user_dn)
        search_conn.unbind()

        auth_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        auth_conn.unbind()

        roles = resolve_roles_from_ldap_groups(groups)

        return {"username": username, "fullName": display_name, "email": email, "roles": roles}

    except Exception:
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
        headers=jenkins_headers("application/xml"),
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
def create_devops_pipeline(request: DevopsPipelineRequest, db: Session = Depends(get_db)):
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
            content={"error": "Unsupported project_type", "supported_project_types": sorted(allowed_project_types)},
        )

    job_name = request.project_name.strip()
    if not job_name:
        return JSONResponse(status_code=400, content={"error": "project_name is required"})

    env_values, env_error = resolve_environment_catalog_values(db, request.target_env, job_name, request)
    if env_error:
        return JSONResponse(status_code=400, content={"error": env_error, "status": "environment_catalog_missing"})

    missing_catalog_fields = [field for field in ["AWS_REGION", "ECR_REGISTRY", "ECR_REPOSITORY", "ARTIFACT_BUCKET"] if not env_values.get(field)]
    if missing_catalog_fields:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Environment Catalog is missing required deployment settings.",
                "missing_fields": missing_catalog_fields,
                "target_env": env_values["TARGET_ENV"],
            },
        )

    license_doc = merge_request_license(request.dict())
    try:
        validated_license = validate_license(
            license_doc,
            pipeline_name="Devops Pipeline",
            target_env=env_values["TARGET_ENV"],
            requested_features=requested_devops_features(request),
            aws_account_id=env_values.get("AWS_ACCOUNT_ID") or aws_account_id_from_registry(env_values.get("ECR_REGISTRY")),
        )
    except LicenseValidationError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc), "status": "license_denied"})

    license_summary_doc = license_summary(validated_license)
    values = {
        "CLIENT_ID": str(validated_license.get("client_id") or "").strip(),
        "CLIENT_NAME": str(validated_license.get("client_name") or "").strip(),
        "LICENSE_TYPE": str(validated_license.get("license_type") or "").strip(),
        "LICENSE_EXPIRES_AT": str(validated_license.get("expires_at") or "").strip(),
        "LICENSED_PIPELINES": ",".join(validated_license.get("enabled_pipelines") or []),
        "LICENSED_FEATURES": ",".join(validated_license.get("enabled_features") or []),
        "LICENSED_ENVIRONMENTS": ",".join(validated_license.get("allowed_environments") or []),
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
        "ENABLE_SONARQUBE": "false",
        "ENABLE_CHECKMARX": "false",
        "CHECKMARX_TEAM": "",
        "ENABLE_SOAPUI": "false",
        "ENABLE_JMETER": "false",
        "ENABLE_SELENIUM": "false",
        "ENABLE_NEWMAN": "false",
        "ENABLE_RESTASSURED": "false",
        "ENABLE_UFT": "false",
        "ENABLE_TRIVY": "false",
        "ENABLE_OPA": "false",
        "TARGET_ENV": env_values["TARGET_ENV"],
        "NOTIFY_EMAIL": (request.notify_email or "").strip(),
        "NOTIFY_CC": (request.additional_notify_emails or "").strip(),
        "AWS_REGION": env_values["AWS_REGION"],
        "ECR_REGISTRY": env_values["ECR_REGISTRY"],
        "ECR_REPOSITORY": env_values["ECR_REPOSITORY"],
        "ARTIFACT_BUCKET": env_values["ARTIFACT_BUCKET"],
        "CLIENT_AWS_ROLE_ARN": env_values["CLIENT_AWS_ROLE_ARN"],
        "NONPROD_AWS_ROLE_ARN": env_values["NONPROD_AWS_ROLE_ARN"],
        "TARGET_AWS_ROLE_ARN": env_values["TARGET_AWS_ROLE_ARN"],
        "DEV_CLUSTER_NAME": env_values["DEV_CLUSTER_NAME"],
        "QA_CLUSTER_NAME": env_values["QA_CLUSTER_NAME"],
        "STAGE_CLUSTER_NAME": env_values["STAGE_CLUSTER_NAME"],
        "PROD_CLUSTER_NAME": env_values["PROD_CLUSTER_NAME"],
        "NAMESPACE_STRATEGY": env_values["NAMESPACE_STRATEGY"],
        "APP_NAMESPACE": env_values["APP_NAMESPACE"],
        "DEV_NAMESPACE": env_values["DEV_NAMESPACE"],
        "QA_NAMESPACE": env_values["QA_NAMESPACE"],
        "STAGE_NAMESPACE": env_values["STAGE_NAMESPACE"],
        "PROD_NAMESPACE": env_values["PROD_NAMESPACE"],
        "ENABLE_NOTIFICATIONS": str(bool(request.enable_notifications or (request.notify_email or "").strip() or (request.additional_notify_emails or "").strip())).lower(),
        "SNS_TOPIC_ARN": env_values["SNS_TOPIC_ARN"],
    }
    xml_values = {k: escape(v, quote=True) for k, v in values.items()}
    bool_param_names = [
        "ENABLE_SONARQUBE", "ENABLE_CHECKMARX", "ENABLE_SOAPUI", "ENABLE_JMETER",
        "ENABLE_SELENIUM", "ENABLE_NEWMAN", "ENABLE_RESTASSURED", "ENABLE_UFT",
        "ENABLE_TRIVY", "ENABLE_OPA", "ENABLE_NOTIFICATIONS",
    ]
    string_param_names = [name for name in values.keys() if name not in bool_param_names]

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

    params_map = "\n".join([f'  {name}: "${{{name}}}",' for name in values.keys()]).rstrip(',')
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
{params_map}
])
    </script>
    <sandbox>true</sandbox>
  </definition>
</flow-definition>
"""

    job_url = f"{JENKINS_URL}/job/{job_name}/api/json"
    job_check = requests.get(job_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    if job_check.status_code == 200:
        config_response = jenkins_post(f"{JENKINS_URL}/job/{job_name}/config.xml", content_type="application/xml", data=job_config)
        create_status = "updated"
        create_response_code = config_response.status_code
    else:
        create_response = jenkins_post(f"{JENKINS_URL}/createItem?name={job_name}", content_type="application/xml", data=job_config)
        create_status = "created"
        create_response_code = create_response.status_code

    build_response = jenkins_post(f"{JENKINS_URL}/job/{job_name}/buildWithParameters", params=values)

    return {
        "status": f"Devops pipeline {create_status} and triggered",
        "project_name": job_name,
        "project_type": request.project_type,
        "target_env": env_values["TARGET_ENV"],
        "namespace": env_values["APP_NAMESPACE"],
        "license": license_summary_doc,
        "create_response_code": create_response_code,
        "build_response_code": build_response.status_code,
    }

@app.post("/test/devops/pipeline")
def create_test_devops_pipeline(request: TestDevopsPipelineRequest, db: Session = Depends(get_db)):
    allowed_project_types = {
        "Docker",
        "Angular",
        "SpringBoot",
        "SpringBoot-Java11",
        "NodeJs",
        "WebComponent",
    }
    if request.project_type not in allowed_project_types:
        return JSONResponse(status_code=400, content={"error": "Unsupported project_type", "supported_project_types": sorted(allowed_project_types)})

    job_name = f"{request.project_name.strip()}-test"
    if not request.project_name.strip():
        return JSONResponse(status_code=400, content={"error": "project_name is required"})

    env_values, env_error = resolve_environment_catalog_values(db, request.target_env, request.project_name.strip(), request)
    if env_error:
        return JSONResponse(status_code=400, content={"error": env_error, "status": "environment_catalog_missing"})

    missing_catalog_fields = [field for field in ["AWS_REGION", "ARTIFACT_BUCKET", "CLIENT_AWS_ROLE_ARN"] if not env_values.get(field)]
    if missing_catalog_fields:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Environment Catalog is missing required test execution settings.",
                "missing_fields": missing_catalog_fields,
                "target_env": env_values["TARGET_ENV"],
            },
        )

    license_doc = merge_request_license(request.dict())
    try:
        validated_license = validate_license(
            license_doc,
            pipeline_name="Test Devops Pipeline",
            target_env=env_values["TARGET_ENV"],
            requested_features=requested_test_devops_features(request),
            aws_account_id=aws_account_id_from_registry(request.image_uri or "") or env_values.get("AWS_ACCOUNT_ID"),
        )
    except LicenseValidationError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc), "status": "license_denied"})

    notification_requested = bool(
        request.enable_notifications or
        (request.notify_email or "").strip() or
        (request.additional_notify_emails or "").strip()
    )

    values = {
        "CLIENT_ID": str(validated_license.get("client_id") or "").strip(),
        "CLIENT_NAME": str(validated_license.get("client_name") or "").strip(),
        "LICENSE_TYPE": str(validated_license.get("license_type") or "").strip(),
        "LICENSE_EXPIRES_AT": str(validated_license.get("expires_at") or "").strip(),
        "LICENSED_PIPELINES": ",".join(validated_license.get("enabled_pipelines") or []),
        "LICENSED_FEATURES": ",".join(validated_license.get("enabled_features") or []),
        "LICENSED_ENVIRONMENTS": ",".join(validated_license.get("allowed_environments") or []),
        "LICENSE_VALIDATION_MODE": str(validated_license.get("validation_mode") or "unknown"),
        "PROJECT_NAME": request.project_name.strip(),
        "PROJECT_TYPE": request.project_type,
        "REPO_TYPE": request.repo_type,
        "REPO_URL": request.repo_url.strip(),
        "BRANCH": request.branch.strip() or "main",
        "CREDENTIALS_ID": "github-token",
        "PIPELINE_KIND": "TEST_DEVOPS",
        "SERVICE_NAME": "Test Devops Pipeline",
        "REQUESTED_BY": request.requestedBy,
        "ENABLE_SONARQUBE": str(request.ENABLE_SONARQUBE).lower(),
        "ENABLE_CHECKMARX": str(request.ENABLE_CHECKMARX).lower(),
        "CHECKMARX_TEAM": (request.checkmarx_team or "").strip(),
        "ENABLE_SOAPUI": "false",
        "ENABLE_JMETER": str(request.ENABLE_JMETER).lower(),
        "ENABLE_SELENIUM": str(request.ENABLE_SELENIUM).lower(),
        "ENABLE_NEWMAN": str(request.ENABLE_NEWMAN).lower(),
        "ENABLE_RESTASSURED": "false",
        "ENABLE_UFT": "false",
        "ENABLE_TRIVY": str(request.ENABLE_TRIVY).lower(),
        "ENABLE_OPA": str(request.ENABLE_OPA).lower(),
        "IMAGE_URI": (request.image_uri or "").strip(),
        "TARGET_APP_URL": (request.target_app_url or "").strip(),
        "API_BASE_URL": (request.api_base_url or request.target_app_url or "").strip(),
        "JMETER_BASE_URL": (request.target_app_url or request.api_base_url or "").strip(),
        "JMETER_TEST_PLAN": (request.jmeter_test_plan or "").strip(),
        "JMETER_THREADS": str(request.jmeter_threads or "10").strip(),
        "JMETER_RAMP_SECONDS": str(request.jmeter_ramp_seconds or "30").strip(),
        "JMETER_LOOPS": str(request.jmeter_loops or "5").strip(),
        "JMETER_MAX_ERROR_PERCENT": str(request.jmeter_max_error_percent or "1").strip(),
        "JMETER_MAX_AVG_MS": str(request.jmeter_max_avg_ms or "2000").strip(),
        "JMETER_MAX_P95_MS": str(request.jmeter_max_p95_ms or "5000").strip(),
        "NEWMAN_COLLECTION_PATH": (request.newman_collection_path or "").strip(),
        "NEWMAN_ENVIRONMENT_PATH": (request.newman_environment_path or "").strip(),
        "NEWMAN_DATA_FILE": (request.newman_data_file or "").strip(),
        "NEWMAN_TIMEOUT_MS": str(request.newman_timeout_ms or "30000").strip(),
        "NEWMAN_FAIL_ON_ERROR": str(request.newman_fail_on_error).lower(),
        "TARGET_ENV": env_values["TARGET_ENV"],
        "NOTIFY_EMAIL": (request.notify_email or "").strip(),
        "NOTIFY_CC": (request.additional_notify_emails or "").strip(),
        "AWS_REGION": env_values["AWS_REGION"],
        "ARTIFACT_BUCKET": env_values["ARTIFACT_BUCKET"],
        "CLIENT_AWS_ROLE_ARN": env_values["CLIENT_AWS_ROLE_ARN"],
        "NONPROD_AWS_ROLE_ARN": env_values["NONPROD_AWS_ROLE_ARN"],
        "TARGET_AWS_ROLE_ARN": env_values["TARGET_AWS_ROLE_ARN"],
        "ENABLE_NOTIFICATIONS": str(notification_requested).lower(),
        "SNS_TOPIC_ARN": env_values["SNS_TOPIC_ARN"],
    }
    xml_values = {k: escape(v, quote=True) for k, v in values.items()}
    bool_param_names = [
        "ENABLE_SONARQUBE", "ENABLE_CHECKMARX", "ENABLE_SOAPUI", "ENABLE_JMETER",
        "ENABLE_SELENIUM", "ENABLE_NEWMAN", "ENABLE_RESTASSURED", "ENABLE_UFT",
        "ENABLE_TRIVY", "ENABLE_OPA", "ENABLE_NOTIFICATIONS", "NEWMAN_FAIL_ON_ERROR",
    ]
    string_param_names = [name for name in values.keys() if name not in bool_param_names]

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

    params_map = "\n".join([f'  {name}: "${{{name}}}",' for name in values.keys()]).rstrip(',')
    job_config = f"""
<flow-definition plugin="workflow-job">
  <description>Test Devops Pipeline for {xml_values["PROJECT_NAME"]}</description>
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
{params_map}
])
    </script>
    <sandbox>true</sandbox>
  </definition>
</flow-definition>
"""

    job_url = f"{JENKINS_URL}/job/{job_name}/api/json"
    job_check = requests.get(job_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    if job_check.status_code == 200:
        config_response = jenkins_post(f"{JENKINS_URL}/job/{job_name}/config.xml", content_type="application/xml", data=job_config)
        create_status = "updated"
        create_response_code = config_response.status_code
    else:
        create_response = jenkins_post(f"{JENKINS_URL}/createItem?name={job_name}", content_type="application/xml", data=job_config)
        create_status = "created"
        create_response_code = create_response.status_code

    build_response = jenkins_post(f"{JENKINS_URL}/job/{job_name}/buildWithParameters", params=values)

    return {
        "status": f"Test Devops pipeline {create_status} and triggered",
        "project_name": request.project_name.strip(),
        "jenkins_job": job_name,
        "project_type": request.project_type,
        "license": license_summary(validated_license),
        "create_response_code": create_response_code,
        "build_response_code": build_response.status_code,
    }

@app.post("/prod/devops/pipeline")
def create_prod_devops_pipeline(request: ProdDevopsPipelineRequest, db: Session = Depends(get_db)):
    job_name = f"{request.project_name.strip()}-prod"
    if not request.project_name.strip():
        return JSONResponse(status_code=400, content={"error": "project_name is required"})
    if "PROD" not in (request.target_env or "").upper():
        return JSONResponse(status_code=400, content={"error": "Prod DevOps Pipeline only supports PROD target environments"})

    source_env_values, source_env_error = resolve_environment_catalog_values(db, request.source_env, request.project_name.strip(), request)
    if source_env_error:
        return JSONResponse(status_code=400, content={"error": source_env_error, "status": "source_environment_catalog_missing"})
    target_env_values, target_env_error = resolve_environment_catalog_values(db, request.target_env, request.project_name.strip(), request)
    if target_env_error:
        return JSONResponse(status_code=400, content={"error": target_env_error, "status": "target_environment_catalog_missing"})

    missing_catalog_fields = [
        field for field in ["ARTIFACT_BUCKET", "ECR_REGISTRY", "ECR_REPOSITORY", "SOURCE_AWS_ROLE_ARN"]
        if not source_env_values.get(field)
    ]
    missing_catalog_fields += [
        field for field in ["ECR_REGISTRY", "ECR_REPOSITORY", "TARGET_AWS_ROLE_ARN", "PROD_CLUSTER_NAME"]
        if not target_env_values.get(field)
    ]
    if missing_catalog_fields:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Environment Catalog is missing required production promotion settings.",
                "missing_fields": sorted(set(missing_catalog_fields)),
                "source_env": source_env_values["TARGET_ENV"],
                "target_env": target_env_values["TARGET_ENV"],
            },
        )

    license_doc = merge_request_license(request.dict())
    try:
        validated_license = validate_license(
            license_doc,
            pipeline_name="Prod Devops Pipeline",
            target_env=target_env_values["TARGET_ENV"],
            requested_features=requested_prod_devops_features(request),
            aws_account_id=target_env_values.get("AWS_ACCOUNT_ID") or aws_account_id_from_registry(target_env_values.get("ECR_REGISTRY")),
        )
    except LicenseValidationError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc), "status": "license_denied"})

    license_summary_doc = license_summary(validated_license)
    artifact_prefix = request.artifact_prefix.strip().strip("/")
    image_json_path = (request.image_json_path or f"{artifact_prefix}/image.json").strip().lstrip("/")
    template_config_path = (request.template_config_path or f"{artifact_prefix}/templateconfiguration.json").strip().lstrip("/")
    notification_requested = bool(
        request.enable_notifications or
        (request.notify_email or "").strip() or
        (request.additional_notify_emails or "").strip()
    )

    values = {
        "CLIENT_ID": str(validated_license.get("client_id") or "").strip(),
        "CLIENT_NAME": str(validated_license.get("client_name") or "").strip(),
        "LICENSE_TYPE": str(validated_license.get("license_type") or "").strip(),
        "LICENSE_EXPIRES_AT": str(validated_license.get("expires_at") or "").strip(),
        "LICENSED_PIPELINES": ",".join(validated_license.get("enabled_pipelines") or []),
        "LICENSED_FEATURES": ",".join(validated_license.get("enabled_features") or []),
        "LICENSED_ENVIRONMENTS": ",".join(validated_license.get("allowed_environments") or []),
        "LICENSE_VALIDATION_MODE": str(validated_license.get("validation_mode") or "unknown"),
        "PROJECT_NAME": request.project_name.strip(),
        "PIPELINE_KIND": "PROD_DEVOPS",
        "SERVICE_NAME": "Prod Devops Pipeline",
        "REQUESTED_BY": request.requestedBy,
        "ARTIFACT_BUCKET": (request.artifact_bucket or source_env_values["ARTIFACT_BUCKET"]).strip(),
        "ARTIFACT_PREFIX": artifact_prefix,
        "IMAGE_JSON_PATH": image_json_path,
        "TEMPLATE_CONFIG_PATH": template_config_path,
        "SOURCE_ENV": source_env_values["TARGET_ENV"],
        "TARGET_ENV": target_env_values["TARGET_ENV"],
        "AWS_REGION": target_env_values["AWS_REGION"] or source_env_values["AWS_REGION"] or "us-east-1",
        "SOURCE_ECR_REGISTRY": (request.source_ecr_registry or source_env_values["ECR_REGISTRY"]).strip(),
        "SOURCE_ECR_REPOSITORY": (request.source_ecr_repository or source_env_values["ECR_REPOSITORY"]).strip(),
        "TARGET_ECR_REGISTRY": (request.target_ecr_registry or target_env_values["ECR_REGISTRY"]).strip(),
        "TARGET_ECR_REPOSITORY": (request.target_ecr_repository or target_env_values["ECR_REPOSITORY"]).strip(),
        "SOURCE_IMAGE_TAG": (request.source_image_tag or "").strip(),
        "TARGET_IMAGE_TAG": request.target_image_tag.strip() or "prod",
        "CLIENT_AWS_ROLE_ARN": (request.client_aws_role_arn or target_env_values["CLIENT_AWS_ROLE_ARN"] or source_env_values["CLIENT_AWS_ROLE_ARN"]).strip(),
        "SOURCE_AWS_ROLE_ARN": (request.source_aws_role_arn or source_env_values["SOURCE_AWS_ROLE_ARN"] or source_env_values["CLIENT_AWS_ROLE_ARN"]).strip(),
        "TARGET_AWS_ROLE_ARN": (request.target_aws_role_arn or target_env_values["TARGET_AWS_ROLE_ARN"] or target_env_values["CLIENT_AWS_ROLE_ARN"]).strip(),
        "DEV_CLUSTER_NAME": source_env_values["DEV_CLUSTER_NAME"] or target_env_values["DEV_CLUSTER_NAME"],
        "QA_CLUSTER_NAME": source_env_values["QA_CLUSTER_NAME"] or target_env_values["QA_CLUSTER_NAME"],
        "STAGE_CLUSTER_NAME": source_env_values["STAGE_CLUSTER_NAME"] or target_env_values["STAGE_CLUSTER_NAME"],
        "PROD_CLUSTER_NAME": target_env_values["PROD_CLUSTER_NAME"],
        "NAMESPACE_STRATEGY": target_env_values["NAMESPACE_STRATEGY"],
        "APP_NAMESPACE": target_env_values["APP_NAMESPACE"],
        "DEV_NAMESPACE": source_env_values["DEV_NAMESPACE"] or target_env_values["DEV_NAMESPACE"],
        "QA_NAMESPACE": source_env_values["QA_NAMESPACE"] or target_env_values["QA_NAMESPACE"],
        "STAGE_NAMESPACE": source_env_values["STAGE_NAMESPACE"] or target_env_values["STAGE_NAMESPACE"],
        "PROD_NAMESPACE": target_env_values["PROD_NAMESPACE"],
        "SECRET_ENABLED": str(request.secret_enabled).lower(),
        "XID_ARRAY": (request.xid_array or "").strip(),
        "APPROVER": (request.approver or "").strip(),
        "NOTIFY_EMAIL": (request.notify_email or "").strip(),
        "NOTIFY_CC": (request.additional_notify_emails or "").strip(),
        "ENABLE_NOTIFICATIONS": str(notification_requested).lower(),
        "SNS_TOPIC_ARN": target_env_values["SNS_TOPIC_ARN"] or source_env_values["SNS_TOPIC_ARN"] or (request.sns_topic_arn or "").strip(),
    }
    xml_values = {k: escape(v, quote=True) for k, v in values.items()}

    bool_param_names = ["SECRET_ENABLED", "ENABLE_NOTIFICATIONS"]
    string_param_names = [name for name in values.keys() if name not in bool_param_names]

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
  <description>Prod Devops Pipeline for {xml_values["PROJECT_NAME"]}</description>
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
  PIPELINE_KIND: "${{PIPELINE_KIND}}",
  SERVICE_NAME: "${{SERVICE_NAME}}",
  REQUESTED_BY: "${{REQUESTED_BY}}",
  ARTIFACT_BUCKET: "${{ARTIFACT_BUCKET}}",
  ARTIFACT_PREFIX: "${{ARTIFACT_PREFIX}}",
  IMAGE_JSON_PATH: "${{IMAGE_JSON_PATH}}",
  TEMPLATE_CONFIG_PATH: "${{TEMPLATE_CONFIG_PATH}}",
  SOURCE_ENV: "${{SOURCE_ENV}}",
  TARGET_ENV: "${{TARGET_ENV}}",
  AWS_REGION: "${{AWS_REGION}}",
  SOURCE_ECR_REGISTRY: "${{SOURCE_ECR_REGISTRY}}",
  SOURCE_ECR_REPOSITORY: "${{SOURCE_ECR_REPOSITORY}}",
  TARGET_ECR_REGISTRY: "${{TARGET_ECR_REGISTRY}}",
  TARGET_ECR_REPOSITORY: "${{TARGET_ECR_REPOSITORY}}",
  SOURCE_IMAGE_TAG: "${{SOURCE_IMAGE_TAG}}",
  TARGET_IMAGE_TAG: "${{TARGET_IMAGE_TAG}}",
  CLIENT_AWS_ROLE_ARN: "${{CLIENT_AWS_ROLE_ARN}}",
  SOURCE_AWS_ROLE_ARN: "${{SOURCE_AWS_ROLE_ARN}}",
  TARGET_AWS_ROLE_ARN: "${{TARGET_AWS_ROLE_ARN}}",
  DEV_CLUSTER_NAME: "${{DEV_CLUSTER_NAME}}",
  QA_CLUSTER_NAME: "${{QA_CLUSTER_NAME}}",
  STAGE_CLUSTER_NAME: "${{STAGE_CLUSTER_NAME}}",
  PROD_CLUSTER_NAME: "${{PROD_CLUSTER_NAME}}",
  NAMESPACE_STRATEGY: "${{NAMESPACE_STRATEGY}}",
  APP_NAMESPACE: "${{APP_NAMESPACE}}",
  DEV_NAMESPACE: "${{DEV_NAMESPACE}}",
  QA_NAMESPACE: "${{QA_NAMESPACE}}",
  STAGE_NAMESPACE: "${{STAGE_NAMESPACE}}",
  PROD_NAMESPACE: "${{PROD_NAMESPACE}}",
  SECRET_ENABLED: "${{SECRET_ENABLED}}",
  XID_ARRAY: "${{XID_ARRAY}}",
  APPROVER: "${{APPROVER}}",
  NOTIFY_EMAIL: "${{NOTIFY_EMAIL}}",
  NOTIFY_CC: "${{NOTIFY_CC}}",
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
        config_response = jenkins_post(
            f"{JENKINS_URL}/job/{job_name}/config.xml",
            content_type="application/xml",
            data=job_config,
        )
        create_status = "updated"
        create_response_code = config_response.status_code
    else:
        create_response = jenkins_post(
            f"{JENKINS_URL}/createItem?name={job_name}",
            content_type="application/xml",
            data=job_config,
        )
        create_status = "created"
        create_response_code = create_response.status_code

    build_response = jenkins_post(
        f"{JENKINS_URL}/job/{job_name}/buildWithParameters",
        params=values,
    )

    return {
        "status": f"Prod Devops pipeline {create_status} and triggered",
        "project_name": request.project_name,
        "job_name": job_name,
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
    build_trigger = requests.post(build_url, headers=jenkins_headers(), auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
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
                source=normalize_security_category(risk.source or "Policy Violation", risk.package_name, risk.violation),
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
    "TRIVY-FILESYSTEM": "Dependency Vulnerability",
    "TRIVY-MISCONFIGURATION": "IaC Misconfiguration",
    "TRIVY-IAC": "IaC Misconfiguration",
    "TRIVY-SECRET": "Secret Exposure",
    "DEPENDENCY VULNERABILITY": "Dependency Vulnerability",
    "CONTAINER VULNERABILITY": "Container Vulnerability",
    "IAC MISCONFIGURATION": "IaC Misconfiguration",
    "SECRET EXPOSURE": "Secret Exposure",
    "SONARQUBE": "Code Security Finding",
    "CODE SECURITY FINDING": "Code Security Finding",
    "OPA": "Policy Violation",
    "OPA-KUBERNETES": "Policy Violation",
    "POLICY VIOLATION": "Policy Violation",
    "CHECKMARX": "Static Code Security Finding",
    "STATIC CODE SECURITY FINDING": "Static Code Security Finding",
}

def normalize_security_category(source: Optional[str], package_name: Optional[str], vulnerability_id: Optional[str]) -> str:
    source_key = (source or "").strip().upper()
    if source_key in SECURITY_CATEGORY_BY_SOURCE:
        return SECURITY_CATEGORY_BY_SOURCE[source_key]
    if (package_name or "").lower().endswith("policy") or "policy" in (vulnerability_id or "").lower():
        return "Policy Violation"
    if "secret" in (package_name or "").lower() or "secret" in (vulnerability_id or "").lower():
        return "Secret Exposure"
    if "misconfig" in (vulnerability_id or "").lower() or "avd-" in (vulnerability_id or "").lower():
        return "IaC Misconfiguration"
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
                source=normalize_security_category(v.source, v.package_name, v.vulnerability_id),
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

        response = requests.post(jenkins_url, headers=jenkins_headers(), auth=(JENKINS_USER, JENKINS_TOKEN), params=params, verify=False)

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
# from typing import List, Optional, Dict, Any
# import os
# import requests
# import json
# from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.utils.conv import escape_filter_chars

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
#         headers=jenkins_headers("application/xml"),
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
# #         headers=jenkins_headers("application/xml"),
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
#     build_trigger = requests.post(build_url, headers=jenkins_headers(), auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)

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
