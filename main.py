from fastapi import FastAPI, Request, Depends, Header, APIRouter, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import os
import requests
import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, NoRegionError
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.utils.conv import escape_filter_chars
import logging
import json
import base64
import hmac
import hashlib
import re
import threading
import time
from html import escape

from database import SessionLocal, engine, Base
from models import Application, ApplicationUserAccess, Vulnerability, EnvironmentCatalog
from cloud_migration import build_cloud_migration_router
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


def ensure_environment_catalog_schema() -> None:
    """Keep the lightweight SQLite catalog compatible with older installed releases."""
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(environment_catalog)")).fetchall()
        }
        additions = {
            "iam_validation_mode": "ALTER TABLE environment_catalog ADD COLUMN iam_validation_mode VARCHAR DEFAULT 'validation-only'",
            "eks_access_mode": "ALTER TABLE environment_catalog ADD COLUMN eks_access_mode VARCHAR DEFAULT 'namespace-scoped'",
        }
        for column, ddl in additions.items():
            if column not in columns:
                connection.execute(text(ddl))


ensure_environment_catalog_schema()


def ensure_vulnerability_schema() -> None:
    """Add optional enterprise finding metadata columns for existing client installs."""
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(vulnerabilities)")).fetchall()
        }
        additions = {
            "policy_bundle": "ALTER TABLE vulnerabilities ADD COLUMN policy_bundle VARCHAR",
            "policy_version": "ALTER TABLE vulnerabilities ADD COLUMN policy_version VARCHAR",
            "policy_ref": "ALTER TABLE vulnerabilities ADD COLUMN policy_ref VARCHAR",
            "policy_decision": "ALTER TABLE vulnerabilities ADD COLUMN policy_decision VARCHAR",
            "waiver_status": "ALTER TABLE vulnerabilities ADD COLUMN waiver_status VARCHAR",
            "waiver_expiry": "ALTER TABLE vulnerabilities ADD COLUMN waiver_expiry VARCHAR",
            "waiver_reason": "ALTER TABLE vulnerabilities ADD COLUMN waiver_reason TEXT",
            "waiver_approved_by": "ALTER TABLE vulnerabilities ADD COLUMN waiver_approved_by VARCHAR",
            "evidence_uri": "ALTER TABLE vulnerabilities ADD COLUMN evidence_uri VARCHAR",
        }
        for column, ddl in additions.items():
            if column not in columns:
                connection.execute(text(ddl))


ensure_vulnerability_schema()

# Jenkins configuration
JENKINS_URL = os.getenv("JENKINS_URL", "https://horizonrelevance.com/jenkins")
JENKINS_USER = os.getenv("JENKINS_USER")
JENKINS_TOKEN = os.getenv("JENKINS_TOKEN")
JENKINS_EXECUTION_MODE = os.getenv("JENKINS_EXECUTION_MODE", "runner").strip().lower() or "runner"
HORIZON_RUNNER_URL = os.getenv("HORIZON_RUNNER_URL", "http://horizon-runner:8080").strip() or "http://horizon-runner:8080"
JENKINS_RUNTIME_ROLE_ARN = os.getenv("JENKINS_RUNTIME_ROLE_ARN", "").strip()
ENVIRONMENT_PREFLIGHT_ENFORCED = os.getenv("ENVIRONMENT_PREFLIGHT_ENFORCED", "false").strip().lower() == "true"
ENVIRONMENT_IAM_MODE = os.getenv("ENVIRONMENT_IAM_MODE", "validation-only").strip() or "validation-only"
ENVIRONMENT_EKS_ACCESS_MODE = os.getenv("ENVIRONMENT_EKS_ACCESS_MODE", "namespace-scoped").strip() or "namespace-scoped"
RBAC_ENFORCEMENT_ENABLED = os.getenv("BACKEND_RBAC_ENFORCEMENT_ENABLED", "true").strip().lower() == "true"
SESSION_TTL_SECONDS = int(os.getenv("BACKEND_SESSION_TTL_SECONDS", "43200"))

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
        timeout=60,
    )

def trigger_jenkins_parameterized_build(job_name: str, values: Dict[str, Any]) -> requests.Response:
    return jenkins_post(
        f"{JENKINS_URL}/job/{job_name}/buildWithParameters",
        content_type="application/x-www-form-urlencoded",
        data=values,
    )

def jenkins_failure_response(action: str, response: requests.Response):
    body = (response.text or "").strip()
    logger.error("Jenkins %s failed with status %s: %s", action, response.status_code, body[:500])
    return JSONResponse(
        status_code=502,
        content={
            "error": f"Jenkins {action} failed",
            "jenkins_status": response.status_code,
            "jenkins_response": body[:1000],
        },
    )

def groovy_string(value: Any) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

def groovy_single_quoted(value: Any) -> str:
    return str(value or "").replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")

def runner_bool_value(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}

def runner_pipeline_key(values: Dict[str, Any]) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", str(values.get("PIPELINE_KIND") or "").strip().upper()).strip("_")

def runner_stage_plan(values: Dict[str, Any]) -> List[Dict[str, Any]]:
    pipeline_key = runner_pipeline_key(values)
    if pipeline_key in {"TEST", "VALIDATION", "VALIDATE", "TEST_DEVOPS", "TEST_DEVSECOPS"}:
        stages = [{"key": "checkout", "name": "Checkout"}]
        validation_gates = [
            ("ENABLE_SELENIUM", "ui-test", "UI End-to-End Test"),
            ("ENABLE_NEWMAN", "api-test", "API Regression Test"),
            ("ENABLE_JMETER", "performance-test", "Performance Test"),
            ("ENABLE_SONARQUBE", "code-quality", "Code Quality Scan"),
            ("ENABLE_CHECKMARX", "static-security", "Static Security Scan"),
            ("ENABLE_TRIVY", "container-iac", "Container / IaC Vulnerability Scan"),
            ("ENABLE_OPA", "policy-validation", "Policy Validation"),
        ]
        stages.extend(
            {"key": stage_key, "name": stage_name, "continueOnFailure": True}
            for flag, stage_key, stage_name in validation_gates
            if runner_bool_value(values.get(flag))
        )
        stages.append({"key": "validation-results", "name": "Publish Validation Results"})
        return stages

    return [
        {"key": "checkout", "name": "Checkout"},
        {"key": "scan", "name": "Scan"},
        {"key": "build", "name": "Build"},
        {"key": "publish", "name": "Publish"},
        {"key": "deploy", "name": "Deploy"},
    ]

def build_parameter_definitions(values: Dict[str, Any], bool_param_names: List[str]) -> str:
    definitions = []
    bool_params = set(bool_param_names)
    for name, value in values.items():
        default_value = str(value).lower() if name in bool_params else str(value or "")
        escaped_default = escape(default_value, quote=True)
        if name in bool_params:
            definitions.append(f"""
        <hudson.model.BooleanParameterDefinition>
          <name>{name}</name>
          <defaultValue>{escaped_default}</defaultValue>
          <description>{name}</description>
        </hudson.model.BooleanParameterDefinition>""")
        else:
            definitions.append(f"""
        <hudson.model.StringParameterDefinition>
          <name>{name}</name>
          <defaultValue>{escaped_default}</defaultValue>
          <description>{name}</description>
        </hudson.model.StringParameterDefinition>""")
    return "".join(definitions)

def build_runner_job_config(
    *,
    description: str,
    values: Dict[str, Any],
    bool_param_names: List[str],
) -> str:
    parameter_definitions = build_parameter_definitions(values, bool_param_names)
    bool_params = set(bool_param_names)
    parameter_lines = []
    for name in values.keys():
        fallback = "false" if name in bool_params else ""
        parameter_lines.append(
            f'            "{name}": (params.{name} == null ? "{fallback}" : params.{name}.toString()),'
        )
    parameters_block = "\n".join(parameter_lines).rstrip(",")
    pipeline_kind = groovy_string(values.get("PIPELINE_KIND", "DEVOPS"))
    service_name = groovy_string(values.get("SERVICE_NAME", "Horizon Pipeline"))
    runner_url = groovy_string(HORIZON_RUNNER_URL)
    stage_blocks = []
    for stage in runner_stage_plan(values):
        runner_call = f'runHorizonRunnerStage("{groovy_string(stage["key"])}", "{groovy_string(stage["name"])}")'
        if stage.get("continueOnFailure"):
            stage_body = f"""          catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {{
            {runner_call}
          }}"""
        else:
            stage_body = f"          {runner_call}"
        stage_blocks.append(f"""    stage('{groovy_single_quoted(stage["name"])}') {{
      steps {{
        script {{
{stage_body}
        }}
      }}
    }}""")
    stage_blocks_text = "\n".join(stage_blocks)
    script = f"""import groovy.json.JsonOutput

def runHorizonRunnerStage(String stageKey, String stageName) {{
  def request = [
    pipelineType: params.PIPELINE_KIND ?: "{pipeline_kind}",
    pipelineKind: params.PIPELINE_KIND ?: "{pipeline_kind}",
    serviceName: params.SERVICE_NAME ?: "{service_name}",
    requestId: "${{env.JOB_NAME}}-${{env.BUILD_NUMBER}}",
    jobName: env.JOB_NAME,
    buildNumber: env.BUILD_NUMBER,
    buildUrl: env.BUILD_URL,
    executionMode: "thin-runner",
    executionStage: stageKey,
    stageName: stageName,
    parameters: [
{parameters_block}
    ],
    payload: [
{parameters_block}
    ]
  ]
  def requestFile = "horizon-runner-request-${{stageKey}}.json"
  def responseFile = "horizon-runner-response-${{stageKey}}.json"
  writeFile file: requestFile, text: JsonOutput.prettyPrint(JsonOutput.toJson(request))
  withEnv([
    "HORIZON_RUNNER_STAGE=${{stageName}}",
    "HORIZON_RUNNER_REQUEST_FILE=${{requestFile}}",
    "HORIZON_RUNNER_RESPONSE_FILE=${{responseFile}}",
    "HORIZON_RUNNER_URL_DEFAULT={runner_url}"
  ]) {{
    sh label: "Horizon Runner: ${{stageName}}", script: '''
      set -eu
      RUNNER_URL="${{HORIZON_RUNNER_URL:-$HORIZON_RUNNER_URL_DEFAULT}}"
      echo "Calling Horizon Runner stage: $HORIZON_RUNNER_STAGE"
      echo "Runner URL: $RUNNER_URL"
      http_code="$(curl -sS -o "$HORIZON_RUNNER_RESPONSE_FILE" -w "%{{http_code}}" \
        -X POST "$RUNNER_URL/v1/execute" \
        -H 'Content-Type: application/json' \
        --data @"$HORIZON_RUNNER_REQUEST_FILE")" || {{
          rc=$?
          echo "Horizon Runner request failed before an HTTP response. curl exit code: $rc"
          test ! -s "$HORIZON_RUNNER_RESPONSE_FILE" || cat "$HORIZON_RUNNER_RESPONSE_FILE"
          exit "$rc"
        }}
      echo "Horizon Runner HTTP status: $http_code"
      test ! -s "$HORIZON_RUNNER_RESPONSE_FILE" || cat "$HORIZON_RUNNER_RESPONSE_FILE"
      echo
      if command -v python3 >/dev/null 2>&1; then
        python3 - "$HORIZON_RUNNER_RESPONSE_FILE" <<'PY' || true
import json
import sys

try:
    response = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)

reports = ((response.get("reportSummary") or dict()).get("reports") or [])
if reports:
    print("== Horizon validation evidence ==")
for report in reports:
    title = report.get("toolName") or report.get("tool") or "report"
    print("Evidence: %s | status=%s | reportDir=%s" % (title, report.get("status", "unknown"), report.get("reportDir", "n/a")))
    if report.get("totalTests") is not None:
        print(
            "Tests: total=%s passed=%s failed=%s errors=%s skipped=%s duration=%ss" % (
                report.get("totalTests", 0),
                report.get("passedTests", 0),
                report.get("failedTests", 0),
                report.get("errorTests", 0),
                report.get("skippedTests", 0),
                report.get("durationSeconds", 0),
            )
        )
    cases = report.get("testCases") or []
    for test_case in cases[:20]:
        class_name = (test_case.get("className") + " - ") if test_case.get("className") else ""
        print(" - [%s] %s%s" % (test_case.get("status", "UNKNOWN"), class_name, test_case.get("name", "unnamed test")))
    if len(cases) > 20:
        print(" - ... %s more test cases in the published report" % (len(cases) - 20))
    if report.get("s3Uri"):
        print("S3 evidence: %s" % report.get("s3Uri"))
PY
      fi
      case "$http_code" in
        2*) ;;
        *)
          echo "Horizon Runner stage '$HORIZON_RUNNER_STAGE' failed with HTTP $http_code."
          echo "See $HORIZON_RUNNER_RESPONSE_FILE above for the runner error detail."
          exit 1
          ;;
      esac
    '''
  }}
}}

pipeline {{
  agent any
  options {{
    disableConcurrentBuilds()
  }}
  stages {{
{stage_blocks_text}
  }}
  post {{
    always {{
      archiveArtifacts artifacts: 'horizon-runner-request*.json,horizon-runner-response*.json', allowEmptyArchive: true
    }}
  }}
}}
"""
    return f"""
<flow-definition plugin="workflow-job">
  <description>{escape(description, quote=True)}</description>
  <properties>
    <hudson.model.ParametersDefinitionProperty>
      <parameterDefinitions>
        {parameter_definitions}
      </parameterDefinitions>
    </hudson.model.ParametersDefinitionProperty>
  </properties>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
    <script>{escape(script, quote=False)}</script>
    <sandbox>true</sandbox>
  </definition>
</flow-definition>
"""

# GitHub webhook secret
GITHUB_WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]
SESSION_SIGNING_SECRET = os.getenv("BACKEND_SESSION_SECRET", GITHUB_WEBHOOK_SECRET)

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
RBAC_BOOTSTRAP_PLATFORM_ADMINS_RAW = os.getenv("RBAC_BOOTSTRAP_PLATFORM_ADMINS", "")
RBAC_BOOTSTRAP_ROLE_GRANTS_RAW = os.getenv("RBAC_BOOTSTRAP_ROLE_GRANTS", "{}")
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
    source_env: str = "DEV"
    target_env: str = "QA"
    aws_region: str = "us-east-1"
    source_ecr_registry: Optional[str] = None
    source_ecr_repository: Optional[str] = None
    target_ecr_registry: Optional[str] = None
    target_ecr_repository: Optional[str] = None
    source_image_tag: Optional[str] = None
    target_image_tag: Optional[str] = None
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
    require_approval: bool = False
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
    pipeline_name: str = "Build & Deploy Pipeline"
    target_env: str = "EKS-NONPROD"
    requested_features: List[str] = []

class LicenseSyncRequest(BaseModel):
    force: Optional[bool] = False

class LicenseUpgradeRequest(BaseModel):
    requested_plan_code: Optional[str] = "enterprise-annual"
    requested_license_type: Optional[str] = "enterprise"
    requested_environments: Optional[List[str]] = None
    requested_features: Optional[List[str]] = None
    requested_user_count: Optional[int] = 0
    requested_repo_count: Optional[int] = 0
    requester_email: Optional[str] = None
    message: Optional[str] = ""
    metadata: Optional[Dict[str, Any]] = None

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
    iam_validation_mode: Optional[str] = "validation-only"
    eks_access_mode: Optional[str] = "namespace-scoped"
    sns_topic_arn: Optional[str] = None
    is_active: bool = True

class EnvironmentCatalogRequest(BaseModel):
    environments: List[EnvironmentCatalogEntryRequest]

class EnvironmentPreflightRequest(BaseModel):
    project_name: str = "application"
    pipeline_kind: str = "DEVOPS"
    source_env: Optional[str] = None

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
    jenkins_job: Optional[str] = None
    build_number: Optional[int] = None
    jenkins_url: Optional[str] = None
    policy_bundle: Optional[str] = None
    policy_version: Optional[str] = None
    policy_ref: Optional[str] = None
    policy_decision: Optional[str] = None
    waiver_status: Optional[str] = None
    waiver_expiry: Optional[str] = None
    waiver_reason: Optional[str] = None
    waiver_approved_by: Optional[str] = None
    evidence_uri: Optional[str] = None

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

class AuthPrincipal(BaseModel):
    username: str
    email: str = ""
    full_name: str = ""
    roles: List[str] = []
    groups: List[str] = []

ROLE_PLATFORM_ADMIN = "platform-admin"
ROLE_DEVELOPER = "developer"
ROLE_QA = "qa"
ROLE_RELEASE_MANAGER = "release-manager"
ROLE_VIEWER = "viewer"
ROLE_MIGRATION_ARCHITECT = "migration-architect"
ROLE_MIGRATION_OPERATOR = "migration-operator"
ROLE_MIGRATION_APPROVER = "migration-approver"
ROLE_MIGRATION_AUDITOR = "migration-auditor"

CATALOG_ADMIN_ROLES = {ROLE_PLATFORM_ADMIN}
PIPELINE_BUILD_ROLES = {ROLE_PLATFORM_ADMIN, ROLE_DEVELOPER}
PIPELINE_VALIDATE_ROLES = {ROLE_PLATFORM_ADMIN, ROLE_DEVELOPER, ROLE_QA, ROLE_RELEASE_MANAGER}
PIPELINE_RELEASE_ROLES = {ROLE_PLATFORM_ADMIN, ROLE_RELEASE_MANAGER}
SECURITY_READ_ALL_ROLES = {ROLE_PLATFORM_ADMIN, ROLE_QA, ROLE_RELEASE_MANAGER}

ROLE_ENV_PERMISSIONS = {
    ROLE_PLATFORM_ADMIN: {"DEV", "QA", "STAGE", "PROD"},
    ROLE_DEVELOPER: {"DEV"},
    ROLE_QA: {"QA", "STAGE"},
    ROLE_RELEASE_MANAGER: {"QA", "STAGE", "PROD"},
    ROLE_VIEWER: set(),
    ROLE_MIGRATION_ARCHITECT: {"DEV", "QA", "STAGE", "PROD"},
    ROLE_MIGRATION_OPERATOR: {"DEV", "QA", "STAGE", "PROD"},
    ROLE_MIGRATION_APPROVER: {"DEV", "QA", "STAGE", "PROD"},
    ROLE_MIGRATION_AUDITOR: set(),
}

def normalize_role_name(role: str) -> str:
    return str(role or "").strip().lower()

def normalize_identity(value: str) -> str:
    return str(value or "").strip().lower()

def parse_identity_list(raw: Any) -> set[str]:
    if not raw:
        return set()
    if isinstance(raw, str):
        values = re.split(r"[,\n;]+", raw)
    elif isinstance(raw, list):
        values = raw
    else:
        return set()
    return {normalize_identity(value) for value in values if normalize_identity(value)}

def parse_bootstrap_role_grants(raw: str) -> Dict[str, set[str]]:
    grants: Dict[str, set[str]] = {}
    if not raw:
        return grants
    try:
        payload = json.loads(raw)
    except Exception as exc:
        logger.warning("Invalid RBAC_BOOTSTRAP_ROLE_GRANTS JSON: %s", exc)
        return grants

    if isinstance(payload, dict):
        iterable = payload.items()
    elif isinstance(payload, list):
        iterable = ((item.get("role"), item.get("users")) for item in payload if isinstance(item, dict))
    else:
        return grants

    for role, users in iterable:
        role_name = normalize_role_name(role)
        if role_name not in ROLE_ENV_PERMISSIONS:
            continue
        identities = parse_identity_list(users)
        if identities:
            grants.setdefault(role_name, set()).update(identities)
    return grants

BOOTSTRAP_ROLE_GRANTS = parse_bootstrap_role_grants(RBAC_BOOTSTRAP_ROLE_GRANTS_RAW)
BOOTSTRAP_PLATFORM_ADMINS = parse_identity_list(RBAC_BOOTSTRAP_PLATFORM_ADMINS_RAW)
if BOOTSTRAP_PLATFORM_ADMINS:
    BOOTSTRAP_ROLE_GRANTS.setdefault(ROLE_PLATFORM_ADMIN, set()).update(BOOTSTRAP_PLATFORM_ADMINS)

PUBLIC_CATALOG_FIELDS = {
    "name",
    "display_name",
    "account_tier",
    "namespace_strategy",
    "iam_validation_mode",
    "eks_access_mode",
    "is_active",
    "updated_at",
}

def normalize_roles(roles: Optional[List[str]]) -> List[str]:
    normalized = sorted({normalize_role_name(role) for role in (roles or []) if normalize_role_name(role)})
    return normalized or [ROLE_VIEWER]

def apply_bootstrap_role_grants(username: str, email: str, roles: Optional[List[str]]) -> List[str]:
    if not BOOTSTRAP_ROLE_GRANTS:
        return normalize_roles(roles)
    identities = {normalize_identity(username), normalize_identity(email)}
    granted_roles = set(normalize_roles(roles))
    for role, allowed_identities in BOOTSTRAP_ROLE_GRANTS.items():
        if identities.intersection(allowed_identities):
            granted_roles.add(role)
    return normalize_roles(list(granted_roles))

def principal_has_role(principal: AuthPrincipal, allowed_roles: set[str]) -> bool:
    return bool(set(normalize_roles(principal.roles)).intersection(allowed_roles))

def principal_can_use_environment(principal: AuthPrincipal, target_env: str) -> bool:
    env = normalize_environment_name(target_env)
    for role in normalize_roles(principal.roles):
        if env in ROLE_ENV_PERMISSIONS.get(role, set()):
            return True
    return False

def principal_can_view_all_findings(principal: AuthPrincipal) -> bool:
    return principal_has_role(principal, SECURITY_READ_ALL_ROLES)

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def _b64url_decode(value: str) -> bytes:
    normalized = value.encode("utf-8")
    normalized += b"=" * (-len(normalized) % 4)
    return base64.urlsafe_b64decode(normalized)

def create_session_token(principal: AuthPrincipal) -> str:
    now = int(time.time())
    claims = {
        "sub": principal.username,
        "email": principal.email,
        "full_name": principal.full_name,
        "roles": normalize_roles(principal.roles),
        "groups": principal.groups,
        "iat": now,
        "exp": now + SESSION_TTL_SECONDS,
    }
    payload = _b64url_encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(SESSION_SIGNING_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return f"{payload}.{_b64url_encode(signature)}"

def decode_session_token(token: str) -> AuthPrincipal:
    try:
        payload, signature = token.split(".", 1)
        expected_signature = _b64url_encode(
            hmac.new(SESSION_SIGNING_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("invalid signature")
        claims = json.loads(_b64url_decode(payload).decode("utf-8"))
        if int(claims.get("exp") or 0) < int(time.time()):
            raise ValueError("expired token")
        return AuthPrincipal(
            username=str(claims.get("sub") or ""),
            email=str(claims.get("email") or ""),
            full_name=str(claims.get("full_name") or ""),
            roles=normalize_roles(claims.get("roles") or []),
            groups=claims.get("groups") or [],
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session token.") from exc

def get_current_principal(authorization: Optional[str] = Header(None)) -> AuthPrincipal:
    if not RBAC_ENFORCEMENT_ENABLED:
        return AuthPrincipal(username="system", email="", full_name="System", roles=[ROLE_PLATFORM_ADMIN])
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    return decode_session_token(token)

def require_roles(*allowed_roles: str):
    allowed = {normalize_role_name(role) for role in allowed_roles}

    def dependency(principal: AuthPrincipal = Depends(get_current_principal)) -> AuthPrincipal:
        if not principal_has_role(principal, allowed):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {', '.join(sorted(allowed))}",
            )
        return principal

    return dependency


app.include_router(build_cloud_migration_router(get_current_principal, get_db))

def require_environment_permission(principal: AuthPrincipal, target_env: str, action: str) -> None:
    if not principal_can_use_environment(principal, target_env):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{action} is not allowed for environment {normalize_environment_name(target_env)} with current roles.",
        )

def principal_email(principal: AuthPrincipal) -> str:
    return principal.email or f"{principal.username}@local"

def sanitize_catalog_entry_for_principal(entry: Dict[str, Any], principal: AuthPrincipal) -> Dict[str, Any]:
    if principal_has_role(principal, CATALOG_ADMIN_ROLES):
        return entry
    return {key: value for key, value in entry.items() if key in PUBLIC_CATALOG_FIELDS}

def sanitize_preflight_for_principal(preflight: Dict[str, Any], principal: AuthPrincipal) -> Dict[str, Any]:
    if principal_has_role(principal, CATALOG_ADMIN_ROLES):
        return preflight
    sanitized = dict(preflight)
    sanitized.pop("resolved", None)
    return sanitized

def ensure_application_registered(
    db: Session,
    *,
    name: str,
    owner_email: str,
    repo_url: str,
    branch: str,
    app_type: str = "unknown",
) -> Application:
    app_entry = db.query(Application).filter_by(name=name).first()
    if not app_entry and repo_url:
        app_entry = db.query(Application).filter_by(repo_url=repo_url).first()
    if not app_entry:
        app_entry = Application(
            name=name,
            description="Registered from Horizon pipeline request",
            owner_email=owner_email,
            repo_url=repo_url,
            branch=branch,
            app_type=app_type or "unknown",
        )
        db.add(app_entry)
        db.commit()
        db.refresh(app_entry)
    else:
        app_entry.owner_email = app_entry.owner_email or owner_email
        app_entry.repo_url = app_entry.repo_url or repo_url
        app_entry.branch = branch or app_entry.branch
        app_entry.app_type = app_type or app_entry.app_type
        db.commit()
        db.refresh(app_entry)

    existing_access = db.query(ApplicationUserAccess).filter_by(
        user_email=owner_email,
        application_id=app_entry.id,
    ).first()
    if not existing_access:
        db.add(ApplicationUserAccess(user_email=owner_email, application_id=app_entry.id))
        db.commit()
    return app_entry

def application_ids_for_principal(db: Session, principal: AuthPrincipal) -> List[int]:
    if principal_can_view_all_findings(principal):
        return [row.id for row in db.query(Application.id).all()]
    email = principal_email(principal)
    rows = db.query(ApplicationUserAccess.application_id).filter_by(user_email=email).all()
    owned = db.query(Application.id).filter_by(owner_email=email).all()
    return sorted({row.application_id for row in rows}.union({row.id for row in owned}))

def authorized_vulnerability_query(db: Session, principal: AuthPrincipal):
    if principal_can_view_all_findings(principal):
        return db.query(Vulnerability)
    allowed_ids = application_ids_for_principal(db, principal)
    if not allowed_ids:
        return db.query(Vulnerability).filter(False)
    return db.query(Vulnerability).filter(Vulnerability.application_id.in_(allowed_ids))

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


def render_ldap_group_search_filter(user_dn: str) -> str:
    escaped_user_dn = escape_filter_chars(user_dn)
    configured_filter = (LDAP_GROUP_SEARCH_FILTER or "(objectClass=groupOfNames)").strip()
    if any(token in configured_filter for token in ("{user_dn}", "{user_dn_escaped}", "{0}")):
        return (
            configured_filter
            .replace("{user_dn_escaped}", escaped_user_dn)
            .replace("{user_dn}", escaped_user_dn)
            .replace("{0}", escaped_user_dn)
        )
    return f"(&{configured_filter}({LDAP_GROUP_MEMBER_ATTRIBUTE}={escaped_user_dn}))"


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
            search_filter=render_ldap_group_search_filter(user_dn),
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
        "iam_validation_mode": entry.iam_validation_mode or ENVIRONMENT_IAM_MODE,
        "eks_access_mode": entry.eks_access_mode or ENVIRONMENT_EKS_ACCESS_MODE,
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
        {"name": "DEV", "display_name": "Development", "account_tier": "nonprod", "iam_validation_mode": ENVIRONMENT_IAM_MODE, "eks_access_mode": ENVIRONMENT_EKS_ACCESS_MODE},
        {"name": "QA", "display_name": "Quality Assurance", "account_tier": "nonprod", "iam_validation_mode": ENVIRONMENT_IAM_MODE, "eks_access_mode": ENVIRONMENT_EKS_ACCESS_MODE},
        {"name": "STAGE", "display_name": "Stage", "account_tier": "nonprod", "iam_validation_mode": ENVIRONMENT_IAM_MODE, "eks_access_mode": ENVIRONMENT_EKS_ACCESS_MODE},
        {"name": "PROD", "display_name": "Production", "account_tier": "prod", "iam_validation_mode": ENVIRONMENT_IAM_MODE, "eks_access_mode": ENVIRONMENT_EKS_ACCESS_MODE},
    ]


def upsert_environment_catalog_entry(db: Session, raw: Dict[str, Any]) -> EnvironmentCatalog:
    env_name = normalize_environment_name(raw.get("name"))
    entry = db.query(EnvironmentCatalog).filter(EnvironmentCatalog.name == env_name).first()
    if not entry:
        entry = EnvironmentCatalog(name=env_name)
        db.add(entry)
    field_aliases = {
        "display_name": ["displayName"],
        "account_tier": ["accountTier"],
        "aws_account_id": ["awsAccountId"],
        "aws_region": ["awsRegion"],
        "ecr_registry": ["ecrRegistry"],
        "ecr_repository_template": ["ecrRepositoryTemplate"],
        "artifact_bucket": ["artifactBucket"],
        "client_aws_role_arn": ["clientAwsRoleArn"],
        "nonprod_aws_role_arn": ["nonprodAwsRoleArn"],
        "source_aws_role_arn": ["sourceAwsRoleArn"],
        "target_aws_role_arn": ["targetAwsRoleArn"],
        "cluster_name": ["clusterName"],
        "namespace_strategy": ["namespaceStrategy"],
        "namespace_template": ["namespaceTemplate"],
        "iam_validation_mode": ["iamValidationMode"],
        "eks_access_mode": ["eksAccessMode"],
        "sns_topic_arn": ["snsTopicArn"],
    }
    allowed_fields = [
        "display_name", "account_tier", "aws_account_id", "aws_region", "ecr_registry",
        "ecr_repository_template", "artifact_bucket", "client_aws_role_arn", "nonprod_aws_role_arn",
        "source_aws_role_arn", "target_aws_role_arn", "cluster_name", "namespace_strategy",
        "namespace_template", "iam_validation_mode", "eks_access_mode", "sns_topic_arn",
    ]
    for field in allowed_fields:
        value = raw.get(field)
        if value is None:
            for alias in field_aliases.get(field, []):
                value = raw.get(alias)
                if value is not None:
                    break
        if value is not None:
            setattr(entry, field, str(value).strip())
    is_active_value = raw.get("is_active", raw.get("isActive", True))
    entry.is_active = 1 if is_active_value else 0
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
    iam_validation_mode = resolved("iam_validation_mode", ENVIRONMENT_IAM_MODE)
    eks_access_mode = resolved("eks_access_mode", ENVIRONMENT_EKS_ACCESS_MODE)
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
        "IAM_VALIDATION_MODE": iam_validation_mode,
        "EKS_ACCESS_MODE": eks_access_mode,
        "APP_NAMESPACE": namespace,
        "DEV_NAMESPACE": namespaces["DEV"] or request_value("dev_namespace"),
        "QA_NAMESPACE": namespaces["QA"] or request_value("qa_namespace"),
        "STAGE_NAMESPACE": namespaces["STAGE"] or request_value("stage_namespace"),
        "PROD_NAMESPACE": namespaces["PROD"] or request_value("prod_namespace"),
        "SNS_TOPIC_ARN": resolved("sns_topic_arn", request_value("sns_topic_arn")),
        "catalog": catalog,
    }, None


def normalize_ecr_registry(registry: Optional[str], region: str) -> str:
    registry_value = (registry or "").strip()
    if re.fullmatch(r"[0-9]{12}", registry_value):
        return f"{registry_value}.dkr.ecr.{region}.amazonaws.com"
    return registry_value


def deployment_role_from_values(env_values: Dict[str, Any]) -> str:
    return (
        env_values.get("TARGET_AWS_ROLE_ARN")
        or env_values.get("NONPROD_AWS_ROLE_ARN")
        or env_values.get("CLIENT_AWS_ROLE_ARN")
        or env_values.get("SOURCE_AWS_ROLE_ARN")
        or ""
    ).strip()


def preflight_check(
    name: str,
    status: str,
    message: str,
    required: bool = True,
    remediation: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "required": required,
        "message": message,
        "remediation": remediation or "",
        "details": details or {},
    }


def summarize_preflight(checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    blocking = [check for check in checks if check["required"] and check["status"] == "FAIL"]
    warnings = [check for check in checks if check["status"] == "WARN"]
    if blocking:
        return {"ready": False, "status": "not_ready"}
    if warnings:
        return {"ready": True, "status": "ready_with_warnings"}
    return {"ready": True, "status": "ready"}


def assume_role_session(role_arn: str, region: str):
    sts_client = boto3.client("sts", region_name=region)
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"horizon-preflight-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        DurationSeconds=900,
    )
    credentials = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )


def run_environment_preflight(
    db: Session,
    target_env: str,
    project_name: str = "application",
    request: Optional[BaseModel] = None,
    pipeline_kind: str = "DEVOPS",
) -> Dict[str, Any]:
    env_values, env_error = resolve_environment_catalog_values(db, target_env, project_name, request)
    checks: List[Dict[str, Any]] = []
    env = normalize_environment_name(target_env)

    if env_error:
        checks.append(preflight_check(
            "Environment catalog",
            "FAIL",
            env_error,
            remediation="A platform admin must save this environment in Environment Catalog before developers can run pipelines.",
        ))
        summary = summarize_preflight(checks)
        return {
            **summary,
            "target_env": env,
            "project_name": project_name,
            "pipeline_kind": pipeline_kind,
            "enforcement_enabled": ENVIRONMENT_PREFLIGHT_ENFORCED,
            "checks": checks,
        }

    region = env_values.get("AWS_REGION") or "us-east-1"
    namespace = env_values.get("APP_NAMESPACE") or ""
    deployment_role = deployment_role_from_values(env_values)
    ecr_registry = normalize_ecr_registry(env_values.get("ECR_REGISTRY"), region)
    ecr_repository = env_values.get("ECR_REPOSITORY") or ""
    artifact_bucket = env_values.get("ARTIFACT_BUCKET") or ""
    cluster_name = (
        env_values.get(f"{env}_CLUSTER_NAME")
        or env_values.get("DEV_CLUSTER_NAME")
        or env_values.get("QA_CLUSTER_NAME")
        or env_values.get("STAGE_CLUSTER_NAME")
        or env_values.get("PROD_CLUSTER_NAME")
        or ""
    )
    iam_mode = env_values.get("IAM_VALIDATION_MODE") or ENVIRONMENT_IAM_MODE
    eks_access_mode = env_values.get("EKS_ACCESS_MODE") or ENVIRONMENT_EKS_ACCESS_MODE

    required_fields = {
        "AWS region": region,
        "Artifact bucket": artifact_bucket,
        "Deployment role ARN": deployment_role,
        "EKS cluster name": cluster_name,
        "Namespace": namespace,
    }
    if pipeline_kind.upper() in {"DEVOPS", "PROD_DEVOPS"}:
        required_fields["ECR registry"] = ecr_registry
        required_fields["ECR repository"] = ecr_repository

    missing = [label for label, value in required_fields.items() if not str(value or "").strip()]
    checks.append(preflight_check(
        "Required catalog fields",
        "FAIL" if missing else "PASS",
        "Missing required fields: " + ", ".join(missing) if missing else "All required deployable environment fields are present.",
        remediation="Update Environment Catalog or installer client-values.yaml with the missing fields.",
        details={"missing": missing},
    ))

    if not JENKINS_USER or not JENKINS_TOKEN or JENKINS_TOKEN == "replace-with-jenkins-api-token":
        checks.append(preflight_check(
            "Jenkins backend secret",
            "FAIL",
            "Backend is missing a real Jenkins API token.",
            remediation="Create/update the Kubernetes secret that provides JENKINS_USER and JENKINS_TOKEN, then restart the backend pod.",
        ))
    else:
        try:
            jenkins_response = requests.get(
                f"{JENKINS_URL}/whoAmI/api/json",
                auth=(JENKINS_USER, JENKINS_TOKEN),
                verify=False,
                timeout=10,
            )
            checks.append(preflight_check(
                "Jenkins API authentication",
                "PASS" if jenkins_response.status_code == 200 else "FAIL",
                "Backend can authenticate to Jenkins." if jenkins_response.status_code == 200 else f"Jenkins returned HTTP {jenkins_response.status_code}.",
                remediation="Regenerate the Jenkins API token and update the backend Kubernetes secret.",
            ))
        except requests.RequestException as exc:
            checks.append(preflight_check(
                "Jenkins API authentication",
                "FAIL",
                f"Backend could not reach Jenkins: {exc}",
                remediation="Validate JENKINS_URL, service routing, and the backend network path to Jenkins.",
            ))

    if not JENKINS_RUNTIME_ROLE_ARN:
        checks.append(preflight_check(
            "Jenkins IRSA role",
            "WARN",
            "JENKINS_RUNTIME_ROLE_ARN is not configured for preflight visibility.",
            required=False,
            remediation="Annotate the Jenkins service account with its IRSA role and set JENKINS_RUNTIME_ROLE_ARN in backend values.",
        ))
    else:
        checks.append(preflight_check(
            "Jenkins IRSA role",
            "PASS",
            "Jenkins runtime role is configured for IRSA-based deployments.",
            required=False,
            details={"role_arn": JENKINS_RUNTIME_ROLE_ARN},
        ))

    if not deployment_role:
        summary = summarize_preflight(checks)
        return {
            **summary,
            "target_env": env,
            "project_name": project_name,
            "pipeline_kind": pipeline_kind,
            "namespace": namespace,
            "iam_validation_mode": iam_mode,
            "eks_access_mode": eks_access_mode,
            "enforcement_enabled": ENVIRONMENT_PREFLIGHT_ENFORCED,
            "checks": checks,
        }

    try:
        validation_session = assume_role_session(deployment_role, region)
        caller = validation_session.client("sts").get_caller_identity()
        checks.append(preflight_check(
            "Deployment role assumption",
            "PASS",
            "Validation runtime can assume the deployment role.",
            details={"account": caller.get("Account"), "assumed_arn": caller.get("Arn")},
        ))

        if artifact_bucket:
            try:
                validation_session.client("s3").head_bucket(Bucket=artifact_bucket)
                checks.append(preflight_check("Artifact bucket access", "PASS", "Deployment role can access the artifact bucket."))
            except ClientError as exc:
                checks.append(preflight_check(
                    "Artifact bucket access",
                    "FAIL",
                    f"Deployment role cannot access bucket '{artifact_bucket}': {exc.response.get('Error', {}).get('Code', 'AccessDenied')}",
                    remediation="Grant the deployment role least-privilege access to the configured artifacts bucket.",
                ))

        if ecr_registry and ecr_repository:
            try:
                ecr_client = validation_session.client("ecr", region_name=region)
                ecr_client.describe_repositories(repositoryNames=[ecr_repository])
                checks.append(preflight_check("Container registry access", "PASS", "Deployment role can read the target container repository."))
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                checks.append(preflight_check(
                    "Container registry access",
                    "WARN" if code == "RepositoryNotFoundException" else "FAIL",
                    "ECR repository does not exist yet; the build pipeline must be allowed to create it."
                    if code == "RepositoryNotFoundException"
                    else f"Deployment role cannot access ECR repository '{ecr_repository}': {code or exc}",
                    required=code != "RepositoryNotFoundException",
                    remediation="Pre-create the ECR repository or grant the deployment role the required ECR permissions.",
                ))

        if cluster_name:
            eks_client = validation_session.client("eks", region_name=region)
            try:
                eks_client.describe_cluster(name=cluster_name)
                checks.append(preflight_check("EKS cluster visibility", "PASS", "Deployment role can describe the target EKS cluster."))
            except ClientError as exc:
                checks.append(preflight_check(
                    "EKS cluster visibility",
                    "FAIL",
                    f"Deployment role cannot describe EKS cluster '{cluster_name}': {exc.response.get('Error', {}).get('Code', 'AccessDenied')}",
                    remediation="Grant eks:DescribeCluster to the deployment role for the target cluster.",
                ))

            try:
                policies = eks_client.list_associated_access_policies(
                    clusterName=cluster_name,
                    principalArn=deployment_role,
                ).get("associatedAccessPolicies", [])
                namespace_policy = False
                cluster_policy = False
                for policy in policies:
                    scope = policy.get("accessScope") or {}
                    scope_type = str(scope.get("type") or "").lower()
                    namespaces = scope.get("namespaces") or []
                    if scope_type == "namespace" and namespace in namespaces:
                        namespace_policy = True
                    if scope_type == "cluster":
                        cluster_policy = True

                if namespace_policy:
                    checks.append(preflight_check(
                        "Namespace-scoped EKS access",
                        "PASS",
                        f"Deployment role is mapped to namespace '{namespace}'.",
                    ))
                elif cluster_policy:
                    checks.append(preflight_check(
                        "Namespace-scoped EKS access",
                        "WARN",
                        "Deployment role has cluster-scoped EKS access. This works, but is broader than the enterprise namespace-scoped model.",
                        required=False,
                        remediation="Associate the role with an EKS access policy scoped to the application namespace.",
                    ))
                else:
                    checks.append(preflight_check(
                        "Namespace-scoped EKS access",
                        "FAIL" if eks_access_mode == "namespace-scoped" else "WARN",
                        f"No EKS access policy was found for namespace '{namespace}'.",
                        required=eks_access_mode == "namespace-scoped",
                        remediation="Map the deployment role into EKS and grant Kubernetes RBAC only for the approved namespace.",
                    ))
            except ClientError as exc:
                checks.append(preflight_check(
                    "Namespace-scoped EKS access",
                    "WARN",
                    f"Unable to validate EKS access policies: {exc.response.get('Error', {}).get('Code', 'AccessDenied')}",
                    required=False,
                    remediation="Installer validation should verify the role mapping and namespace RBAC when this API is not permitted.",
                ))

    except (ClientError, BotoCoreError, NoCredentialsError, NoRegionError) as exc:
        checks.append(preflight_check(
            "Deployment role assumption",
            "FAIL",
            f"Validation runtime cannot assume deployment role '{deployment_role}': {exc}",
            remediation="In validation-only mode, the client-created role must trust the platform validation/Jenkins IRSA role for sts:AssumeRole.",
        ))

    summary = summarize_preflight(checks)
    return {
        **summary,
        "target_env": env,
        "project_name": project_name,
        "pipeline_kind": pipeline_kind,
        "namespace": namespace,
        "iam_validation_mode": iam_mode,
        "eks_access_mode": eks_access_mode,
        "enforcement_enabled": ENVIRONMENT_PREFLIGHT_ENFORCED,
        "resolved": {
            "aws_region": region,
            "aws_account_id": env_values.get("AWS_ACCOUNT_ID"),
            "ecr_registry": ecr_registry,
            "ecr_repository": ecr_repository,
            "artifact_bucket": artifact_bucket,
            "cluster_name": cluster_name,
            "namespace": namespace,
        },
        "checks": checks,
    }


def preflight_blocking_response(preflight: Dict[str, Any]) -> Optional[JSONResponse]:
    if not ENVIRONMENT_PREFLIGHT_ENFORCED or preflight.get("ready"):
        return None
    return JSONResponse(
        status_code=400,
        content={
            "error": "Environment is not ready for pipeline execution.",
            "status": "environment_not_ready",
            "preflight": preflight,
        },
    )


@app.get("/environment-catalog")
def get_environment_catalog(
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(get_current_principal),
):
    ensure_environment_catalog_seeded(db)
    entries = db.query(EnvironmentCatalog).order_by(EnvironmentCatalog.name.asc()).all()
    if not principal_has_role(principal, CATALOG_ADMIN_ROLES):
        entries = [entry for entry in entries if principal_can_use_environment(principal, entry.name)]
    return {
        "environments": [
            sanitize_catalog_entry_for_principal(catalog_entry_to_dict(entry), principal)
            for entry in entries
        ]
    }


@app.get("/environment-catalog/resolve/{target_env}")
def resolve_environment_catalog(
    target_env: str,
    project_name: str = "application",
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
):
    resolved, error = resolve_environment_catalog_values(db, target_env, project_name)
    if error:
        return JSONResponse(status_code=404, content={"error": error})
    return resolved


@app.get("/environment-catalog/preflight/{target_env}")
def get_environment_preflight(
    target_env: str,
    project_name: str = "application",
    pipeline_kind: str = "DEVOPS",
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(get_current_principal),
):
    require_environment_permission(principal, target_env, "Environment preflight")
    preflight = run_environment_preflight(db, target_env, project_name, pipeline_kind=pipeline_kind)
    return sanitize_preflight_for_principal(preflight, principal)


@app.post("/environment-catalog/preflight/{target_env}")
def post_environment_preflight(
    target_env: str,
    request: EnvironmentPreflightRequest,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(get_current_principal),
):
    require_environment_permission(principal, target_env, "Environment preflight")
    preflight = run_environment_preflight(
        db,
        target_env,
        request.project_name,
        request,
        pipeline_kind=request.pipeline_kind,
    )
    return sanitize_preflight_for_principal(preflight, principal)


@app.post("/environment-catalog")
def save_environment_catalog(
    request: EnvironmentCatalogRequest,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
):
    if not request.environments:
        return JSONResponse(status_code=400, content={"error": "At least one environment is required"})
    for environment in request.environments:
        upsert_environment_catalog_entry(db, environment.dict())
    db.commit()
    entries = db.query(EnvironmentCatalog).order_by(EnvironmentCatalog.name.asc()).all()
    return {"status": "saved", "environments": [catalog_entry_to_dict(entry) for entry in entries]}

def _first_non_empty(*values: Optional[str]) -> str:
    for value in values:
        if value and str(value).strip():
            return str(value).strip()
    return ""

def _license_sync_identity(current_license: Dict[str, Any]) -> Dict[str, str]:
    return {
        "client_id": _first_non_empty(os.getenv("ENTERPRISE_CLIENT_ID"), current_license.get("client_id")),
        "client_name": _first_non_empty(os.getenv("ENTERPRISE_CLIENT_NAME"), current_license.get("client_name")),
        "installation_id": _first_non_empty(os.getenv("ENTERPRISE_INSTALLATION_ID"), current_license.get("installation_id")),
        "aws_account_id": _first_non_empty(
            os.getenv("ENTERPRISE_AWS_ACCOUNT_ID"),
            os.getenv("AWS_ACCOUNT_ID"),
            current_license.get("aws_account_id"),
        ),
        "region": _first_non_empty(
            os.getenv("ENTERPRISE_AWS_REGION"),
            os.getenv("AWS_REGION"),
            os.getenv("AWS_DEFAULT_REGION"),
            current_license.get("region"),
        ),
        "product_version": _first_non_empty(os.getenv("ENTERPRISE_PRODUCT_VERSION"), os.getenv("PRODUCT_VERSION")),
    }

def _license_usage_endpoint() -> str:
    explicit_endpoint = os.getenv("ENTERPRISE_LICENSE_USAGE_ENDPOINT", "").strip()
    if explicit_endpoint:
        return explicit_endpoint
    sync_endpoint = os.getenv("ENTERPRISE_LICENSE_SYNC_ENDPOINT", "").strip()
    if sync_endpoint.endswith("/api/v1/licenses/sync"):
        return sync_endpoint.replace("/api/v1/licenses/sync", "/api/v1/licenses/usage")
    return ""

def _license_upgrade_endpoint() -> str:
    explicit_endpoint = os.getenv("ENTERPRISE_LICENSE_UPGRADE_ENDPOINT", "").strip()
    if explicit_endpoint:
        return explicit_endpoint
    sync_endpoint = os.getenv("ENTERPRISE_LICENSE_SYNC_ENDPOINT", "").strip()
    if sync_endpoint.endswith("/api/v1/licenses/sync"):
        return sync_endpoint.replace("/api/v1/licenses/sync", "/api/v1/licenses/upgrade-requests")
    return ""

def _license_usage_reporting_enabled() -> bool:
    return os.getenv("ENTERPRISE_LICENSE_USAGE_REPORTING_ENABLED", "false").strip().lower() == "true"

def _license_auto_sync_enabled() -> bool:
    return os.getenv("ENTERPRISE_LICENSE_AUTO_SYNC_ENABLED", "false").strip().lower() == "true"

def _license_auto_sync_interval_seconds() -> int:
    try:
        return max(300, int(os.getenv("ENTERPRISE_LICENSE_AUTO_SYNC_INTERVAL_SECONDS", "21600")))
    except ValueError:
        return 21600

def _license_cache_grace_hours() -> int:
    try:
        return max(0, int(os.getenv("ENTERPRISE_LICENSE_CACHE_GRACE_HOURS", "72")))
    except ValueError:
        return 72

def _license_usage_status() -> Dict[str, Any]:
    endpoint = _license_usage_endpoint()
    return {
        "usage_reporting_enabled": _license_usage_reporting_enabled(),
        "usage_endpoint_configured": bool(endpoint),
        "auto_sync_enabled": _license_auto_sync_enabled(),
        "auto_sync_interval_seconds": _license_auto_sync_interval_seconds(),
        "cache_grace_hours": _license_cache_grace_hours(),
    }

def report_license_usage(validated_license: Dict[str, Any], event_type: str, *, quantity: int = 1, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    endpoint = _license_usage_endpoint()
    if not _license_usage_reporting_enabled():
        return {"status": "disabled", "reported": False}
    if not endpoint:
        return {"status": "skipped", "reported": False, "reason": "ENTERPRISE_LICENSE_USAGE_ENDPOINT is not configured"}

    current_license = default_license_from_env()
    identity = _license_sync_identity(current_license)
    client_id = _first_non_empty(validated_license.get("client_id"), identity.get("client_id"))
    installation_id = _first_non_empty(validated_license.get("installation_id"), identity.get("installation_id"))
    license_key = _first_non_empty(validated_license.get("license_key"), current_license.get("license_key"))
    if not client_id or not installation_id or not license_key:
        return {
            "status": "skipped",
            "reported": False,
            "reason": "client_id, installation_id, and license_key are required for usage reporting",
        }

    payload = {
        "client_id": client_id,
        "installation_id": installation_id,
        "license_key": license_key,
        "event_type": event_type,
        "quantity": quantity,
        "metadata": metadata or {},
    }
    try:
        response = requests.post(endpoint, json=payload, timeout=10)
        if response.status_code >= 400:
            try:
                response_body = response.json()
            except ValueError:
                response_body = {"error": response.text}
            logger.warning("License usage reporting failed: %s", response_body)
            return {
                "status": "failed",
                "reported": False,
                "license_service_status": response.status_code,
                "error": response_body.get("detail") or response_body.get("error") or "Usage reporting failed",
            }
        try:
            response_body = response.json()
        except ValueError:
            response_body = {}
        response_body.setdefault("status", "recorded")
        response_body["reported"] = True
        return response_body
    except requests.RequestException as exc:
        logger.warning("License usage reporting skipped because Horizon license service is unreachable: %s", exc)
        return {"status": "failed", "reported": False, "error": str(exc)}

def _usage_requester_hash(requested_by: str) -> str:
    if not requested_by:
        return ""
    return hashlib.sha256(requested_by.encode("utf-8")).hexdigest()[:16]

@app.get("/license/status")
def get_license_status(principal: AuthPrincipal = Depends(get_current_principal)):
    license_doc = default_license_from_env()
    try:
        validated = validate_license(
            license_doc,
            pipeline_name="Build & Deploy Pipeline",
            target_env="DEV",
            requested_features=[],
        )
        summary = license_summary(validated)
        summary["sync_available"] = bool(
            os.getenv("ENTERPRISE_LICENSE_MODE", "offline-file").strip().lower() == "online-sync"
            and os.getenv("ENTERPRISE_LICENSE_SYNC_ENDPOINT", "").strip()
            and os.getenv("ENTERPRISE_LICENSE_ACTIVATION_TOKEN", "").strip()
        )
        summary["upgrade_available"] = bool(_license_upgrade_endpoint() and summary.get("client_id"))
        summary.update(_license_usage_status())
        return summary
    except LicenseValidationError as exc:
        license_doc["status"] = "invalid"
        summary = license_summary(license_doc)
        summary["error"] = str(exc)
        summary["sync_available"] = bool(
            os.getenv("ENTERPRISE_LICENSE_MODE", "offline-file").strip().lower() == "online-sync"
            and os.getenv("ENTERPRISE_LICENSE_SYNC_ENDPOINT", "").strip()
            and os.getenv("ENTERPRISE_LICENSE_ACTIVATION_TOKEN", "").strip()
        )
        summary["upgrade_available"] = bool(_license_upgrade_endpoint() and summary.get("client_id"))
        summary.update(_license_usage_status())
        return JSONResponse(status_code=403, content=summary)

@app.post("/license/validate")
def validate_enterprise_license(
    request: LicenseValidationRequest,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
):
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

def _perform_enterprise_license_sync(force: bool = False) -> tuple[int, Dict[str, Any]]:
    license_mode = os.getenv("ENTERPRISE_LICENSE_MODE", "offline-file").strip().lower()
    sync_endpoint = os.getenv("ENTERPRISE_LICENSE_SYNC_ENDPOINT", "").strip()
    activation_token = os.getenv("ENTERPRISE_LICENSE_ACTIVATION_TOKEN", "").strip()
    current_license = default_license_from_env()

    if license_mode != "online-sync":
        return 400, {
                "error": "Online license sync is not enabled for this deployment.",
                "status": "sync_disabled",
                "license_mode": license_mode,
            }
    if not sync_endpoint:
        return 400, {"error": "ENTERPRISE_LICENSE_SYNC_ENDPOINT is required.", "status": "sync_failed"}
    if not activation_token:
        return 400, {"error": "ENTERPRISE_LICENSE_ACTIVATION_TOKEN is required.", "status": "sync_failed"}

    identity = _license_sync_identity(current_license)
    if not identity["client_id"]:
        return 400, {"error": "ENTERPRISE_CLIENT_ID is required for online license sync.", "status": "sync_failed"}
    if not identity["installation_id"]:
        return 400, {"error": "ENTERPRISE_INSTALLATION_ID is required for online license sync.", "status": "sync_failed"}

    payload = {
        "client_id": identity["client_id"],
        "client_name": identity["client_name"],
        "installation_id": identity["installation_id"],
        "activation_token": activation_token,
        "aws_account_id": identity["aws_account_id"],
        "region": identity["region"],
        "product_version": identity["product_version"],
        "current_license_key": current_license.get("license_key", ""),
        "current_expires_at": current_license.get("expires_at", ""),
        "force": bool(force),
        "platform": {
            "product": "Horizon Relevance AI DevSecOps Platform",
            "backend_root_path": "/pipeline/api",
            "license_mode": license_mode,
            "jenkins_url": JENKINS_URL,
            "environment_preflight_enforced": ENVIRONMENT_PREFLIGHT_ENFORCED,
            "environment_iam_mode": ENVIRONMENT_IAM_MODE,
            "environment_eks_access_mode": ENVIRONMENT_EKS_ACCESS_MODE,
        },
    }

    try:
        response = requests.post(sync_endpoint, json=payload, timeout=15)
    except requests.RequestException as exc:
        logger.exception("License sync failed while calling Horizon license service")
        return 502, {"error": f"License service unreachable: {exc}", "status": "sync_failed"}

    if response.status_code >= 400:
        try:
            error_body = response.json()
        except ValueError:
            error_body = {"error": response.text}
        error_body.setdefault("status", "sync_failed")
        return response.status_code, error_body

    try:
        response_body = response.json()
    except ValueError:
        return 502, {"error": "License service returned non-JSON response.", "status": "sync_failed"}

    synced_license = response_body.get("license") or response_body
    synced_license["license_mode"] = "online-sync"

    try:
        validated = validate_license(
            synced_license,
            pipeline_name="Build & Deploy Pipeline",
            target_env=(synced_license.get("allowed_environments") or ["DEV"])[0],
            requested_features=[],
        )
    except LicenseValidationError as exc:
        return 403, {"error": str(exc), "status": "sync_invalid"}

    cached = save_cached_license(validated)
    summary = license_summary(cached)
    summary["status"] = validated.get("status", "active")
    summary["sync_available"] = True
    summary["upgrade_available"] = bool(_license_upgrade_endpoint() and summary.get("client_id"))
    summary["message"] = response_body.get("message", "License synced successfully.")
    summary.update(_license_usage_status())
    return 200, summary

@app.post("/license/sync")
def sync_enterprise_license(
    request: LicenseSyncRequest,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
):
    status_code, body = _perform_enterprise_license_sync(force=bool(request.force))
    if status_code >= 400:
        return JSONResponse(status_code=status_code, content=body)
    return body

def _license_auto_sync_loop() -> None:
    interval = _license_auto_sync_interval_seconds()
    logger.info("Enterprise license auto-sync enabled with %s second interval", interval)
    time.sleep(20)
    while True:
        try:
            status_code, body = _perform_enterprise_license_sync(force=False)
            if status_code >= 400:
                logger.warning("Enterprise license auto-sync failed: %s", body)
            else:
                logger.info("Enterprise license auto-sync completed: %s", body.get("status", "ok"))
        except Exception as exc:
            logger.exception("Enterprise license auto-sync crashed: %s", exc)
        time.sleep(interval)

@app.on_event("startup")
def start_license_auto_sync() -> None:
    if _license_auto_sync_enabled():
        threading.Thread(target=_license_auto_sync_loop, name="license-auto-sync", daemon=True).start()

@app.post("/license/upgrade-request")
def request_license_upgrade(
    request: LicenseUpgradeRequest,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
):
    endpoint = _license_upgrade_endpoint()
    current_license = default_license_from_env()
    identity = _license_sync_identity(current_license)
    if not endpoint:
        return JSONResponse(status_code=400, content={"error": "ENTERPRISE_LICENSE_UPGRADE_ENDPOINT or ENTERPRISE_LICENSE_SYNC_ENDPOINT is required.", "status": "upgrade_unavailable"})
    if not identity["client_id"]:
        return JSONResponse(status_code=400, content={"error": "ENTERPRISE_CLIENT_ID is required before requesting an upgrade.", "status": "upgrade_failed"})
    if not identity["installation_id"]:
        return JSONResponse(status_code=400, content={"error": "ENTERPRISE_INSTALLATION_ID is required before requesting an upgrade.", "status": "upgrade_failed"})

    requested_environments = request.requested_environments or current_license.get("allowed_environments") or []
    requested_features = request.requested_features or current_license.get("enabled_features") or []
    payload = {
        "client_id": identity["client_id"],
        "installation_id": identity["installation_id"],
        "current_license_key": current_license.get("license_key", ""),
        "requested_plan_code": request.requested_plan_code or "enterprise-annual",
        "requested_license_type": request.requested_license_type or "enterprise",
        "requested_environments": requested_environments,
        "requested_features": requested_features,
        "requested_user_count": int(request.requested_user_count or 0),
        "requested_repo_count": int(request.requested_repo_count or 0),
        "requester_email": request.requester_email or "",
        "message": request.message or "",
        "metadata": {
            **(request.metadata or {}),
            "client_name": identity["client_name"],
            "aws_account_id": identity["aws_account_id"],
            "region": identity["region"],
            "product_version": identity["product_version"],
            "license_mode": os.getenv("ENTERPRISE_LICENSE_MODE", "offline-file"),
        },
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=15)
    except requests.RequestException as exc:
        logger.exception("License upgrade request failed while calling Horizon license service")
        return JSONResponse(status_code=502, content={"error": f"License service unreachable: {exc}", "status": "upgrade_failed"})

    try:
        response_body = response.json()
    except ValueError:
        response_body = {"error": response.text}

    if response.status_code >= 400:
        response_body.setdefault("status", "upgrade_failed")
        return JSONResponse(status_code=response.status_code, content=response_body)

    response_body["status"] = response_body.get("status") or "upgrade_requested"
    response_body["message"] = "Upgrade request submitted to Horizon Relevance."
    return response_body

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

        roles = apply_bootstrap_role_grants(username, email, resolve_roles_from_ldap_groups(groups))
        principal = AuthPrincipal(
            username=username,
            email=email,
            full_name=display_name,
            roles=roles,
            groups=groups,
        )

        return {
            "username": username,
            "fullName": display_name,
            "email": email,
            "roles": roles,
            "groups": groups,
            "token": create_session_token(principal),
            "sessionExpiresIn": SESSION_TTL_SECONDS,
        }

    except Exception:
        return JSONResponse(status_code=401, content={"error": "Invalid credentials or server error"})

@app.get("/get_ldap_users")
def get_ldap_users(principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN))):
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
def get_user_applications(
    email: Optional[str] = None,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(get_current_principal),
):
    try:
        requester_email = principal_email(principal)
        print(f"[DEBUG] Incoming email: {email}; authenticated email: {requester_email}")
        if principal_can_view_all_findings(principal):
            apps = db.query(Application.name).all()
            print(f"[DEBUG] Admin access - apps: {apps}")
            return [a.name for a in apps]

        apps = db.query(Application.name).join(ApplicationUserAccess).filter(
            ApplicationUserAccess.user_email == requester_email
        ).all()
        owned_apps = db.query(Application.name).filter(
            Application.owner_email == requester_email
        ).all()
        names = sorted({a.name for a in apps}.union({a.name for a in owned_apps}))
        print(f"[DEBUG] User apps: {names}")
        return names

    except Exception as e:
        print(f"[ERROR] in /my_applications: {e}")
        return JSONResponse(status_code=500, content={"error": "Failed to call backend"})


@app.post("/pipeline")
def create_pipeline(
    request: PipelineRequest,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN, ROLE_DEVELOPER)),
):
    values = {
        "APP_TYPE": request.app_type,
        "REPO_URL": request.repo_url,
        "BRANCH": request.branch,
        "CREDENTIALS_ID": "github-token",
        "PIPELINE_KIND": "DEVOPS",
        "SERVICE_NAME": "Build & Deploy Pipeline",
        "ENABLE_SONARQUBE": str(request.ENABLE_SONARQUBE).lower(),
        "ENABLE_OPA": str(request.ENABLE_OPA).lower(),
        "ENABLE_TRIVY": str(request.ENABLE_TRIVY).lower(),
    }
    bool_param_names = ["ENABLE_SONARQUBE", "ENABLE_OPA", "ENABLE_TRIVY"]
    job_config = build_runner_job_config(
        description=f"Dynamic Jenkins Pipeline for {request.project_name}",
        values=values,
        bool_param_names=bool_param_names,
    )
    create_response = requests.post(
        f"{JENKINS_URL}/createItem?name={request.project_name}",
        headers=jenkins_headers("application/xml"),
        auth=(JENKINS_USER, JENKINS_TOKEN),
        data=job_config,
        verify=False
    )

    build_response = trigger_jenkins_parameterized_build(
        request.project_name,
        {
            "APP_TYPE": request.app_type,
            "REPO_URL": request.repo_url,
            "BRANCH": request.branch,
            "CREDENTIALS_ID": "github-token",
            "ENABLE_SONARQUBE": str(request.ENABLE_SONARQUBE).lower(),
            "ENABLE_OPA": str(request.ENABLE_OPA).lower(),
            "ENABLE_TRIVY": str(request.ENABLE_TRIVY).lower()
        },
    )

    return {
        "status": "Pipeline created and triggered",
        "create_response_code": create_response.status_code,
        "build_response_code": build_response.status_code
    }

@app.post("/devops/pipeline")
def create_devops_pipeline(
    request: DevopsPipelineRequest,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN, ROLE_DEVELOPER)),
):
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
    require_environment_permission(principal, env_values["TARGET_ENV"], "Build & Deploy Pipeline")

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

    preflight = run_environment_preflight(db, request.target_env, job_name, request, pipeline_kind="DEVOPS")
    blocking_preflight = preflight_blocking_response(preflight)
    if blocking_preflight:
        return blocking_preflight

    license_doc = merge_request_license(request.dict())
    try:
        validated_license = validate_license(
            license_doc,
            pipeline_name="Build & Deploy Pipeline",
            target_env=env_values["TARGET_ENV"],
            requested_features=requested_devops_features(request),
            aws_account_id=env_values.get("AWS_ACCOUNT_ID") or aws_account_id_from_registry(env_values.get("ECR_REGISTRY")),
        )
    except LicenseValidationError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc), "status": "license_denied"})

    license_summary_doc = license_summary(validated_license)
    requester = principal.username or request.requestedBy
    requester_notify_email = (request.notify_email or "").strip() or principal_email(principal)
    notification_requested = bool(
        request.enable_notifications or
        requester_notify_email or
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
        "PROJECT_NAME": job_name,
        "PROJECT_TYPE": request.project_type,
        "REPO_TYPE": request.repo_type,
        "REPO_URL": request.repo_url.strip(),
        "BRANCH": request.branch.strip() or "main",
        "CREDENTIALS_ID": "github-token",
        "PIPELINE_KIND": "DEVOPS",
        "SERVICE_NAME": "Build & Deploy Pipeline",
        "REQUESTED_BY": requester,
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
        "NOTIFY_EMAIL": requester_notify_email,
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
        "IAM_VALIDATION_MODE": env_values["IAM_VALIDATION_MODE"],
        "EKS_ACCESS_MODE": env_values["EKS_ACCESS_MODE"],
        "APP_NAMESPACE": env_values["APP_NAMESPACE"],
        "DEV_NAMESPACE": env_values["DEV_NAMESPACE"],
        "QA_NAMESPACE": env_values["QA_NAMESPACE"],
        "STAGE_NAMESPACE": env_values["STAGE_NAMESPACE"],
        "PROD_NAMESPACE": env_values["PROD_NAMESPACE"],
        "ENABLE_NOTIFICATIONS": str(notification_requested).lower(),
        "SNS_TOPIC_ARN": env_values["SNS_TOPIC_ARN"],
    }
    bool_param_names = [
        "ENABLE_SONARQUBE", "ENABLE_CHECKMARX", "ENABLE_SOAPUI", "ENABLE_JMETER",
        "ENABLE_SELENIUM", "ENABLE_NEWMAN", "ENABLE_RESTASSURED", "ENABLE_UFT",
        "ENABLE_TRIVY", "ENABLE_OPA", "ENABLE_NOTIFICATIONS",
    ]
    job_config = build_runner_job_config(
        description=f"Build & Deploy Pipeline for {values['PROJECT_NAME']}",
        values=values,
        bool_param_names=bool_param_names,
    )

    job_url = f"{JENKINS_URL}/job/{job_name}/api/json"
    job_check = requests.get(job_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    if job_check.status_code == 200:
        config_response = jenkins_post(f"{JENKINS_URL}/job/{job_name}/config.xml", content_type="application/xml", data=job_config)
        create_status = "updated"
        create_response_code = config_response.status_code
        create_response_obj = config_response
    else:
        create_response = jenkins_post(f"{JENKINS_URL}/createItem?name={job_name}", content_type="application/xml", data=job_config)
        create_status = "created"
        create_response_code = create_response.status_code
        create_response_obj = create_response

    if create_response_code not in (200, 201, 202):
        return jenkins_failure_response(f"{create_status} job '{job_name}'", create_response_obj)

    build_response = trigger_jenkins_parameterized_build(job_name, values)
    if build_response.status_code not in (200, 201, 202):
        return jenkins_failure_response(f"trigger build for job '{job_name}'", build_response)

    ensure_application_registered(
        db,
        name=job_name,
        owner_email=principal_email(principal),
        repo_url=request.repo_url.strip(),
        branch=request.branch.strip() or "main",
        app_type=request.project_type,
    )

    usage_report = report_license_usage(
        validated_license,
        "pipeline.build_deploy.requested",
        metadata={
            "pipeline_kind": "DEVOPS",
            "project_name": job_name,
            "project_type": request.project_type,
            "target_env": env_values["TARGET_ENV"],
            "namespace": env_values["APP_NAMESPACE"],
            "branch": request.branch.strip() or "main",
            "repo_type": request.repo_type,
            "jenkins_job": job_name,
            "requester_hash": _usage_requester_hash(principal_email(principal)),
        },
    )

    return {
        "status": f"Devops pipeline {create_status} and triggered",
        "project_name": job_name,
        "project_type": request.project_type,
        "target_env": env_values["TARGET_ENV"],
        "namespace": env_values["APP_NAMESPACE"],
        "license": license_summary_doc,
        "usage_report": usage_report,
        "environment_preflight": sanitize_preflight_for_principal(preflight, principal),
        "create_response_code": create_response_code,
        "build_response_code": build_response.status_code,
    }

@app.post("/test/devops/pipeline")
def create_test_devops_pipeline(
    request: TestDevopsPipelineRequest,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN, ROLE_DEVELOPER, ROLE_QA, ROLE_RELEASE_MANAGER)),
):
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
    require_environment_permission(principal, env_values["TARGET_ENV"], "Validation Pipeline")

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

    preflight = run_environment_preflight(db, request.target_env, request.project_name.strip(), request, pipeline_kind="TEST_DEVOPS")
    blocking_preflight = preflight_blocking_response(preflight)
    if blocking_preflight:
        return blocking_preflight

    license_doc = merge_request_license(request.dict())
    try:
        validated_license = validate_license(
            license_doc,
            pipeline_name="Validation Pipeline",
            target_env=env_values["TARGET_ENV"],
            requested_features=requested_test_devops_features(request),
            aws_account_id=aws_account_id_from_registry(request.image_uri or "") or env_values.get("AWS_ACCOUNT_ID"),
        )
    except LicenseValidationError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc), "status": "license_denied"})

    requester = principal.username or request.requestedBy
    requester_notify_email = (request.notify_email or "").strip() or principal_email(principal)
    notification_requested = bool(
        request.enable_notifications or
        requester_notify_email or
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
        "SERVICE_NAME": "Validation Pipeline",
        "REQUESTED_BY": requester,
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
        "NOTIFY_EMAIL": requester_notify_email,
        "NOTIFY_CC": (request.additional_notify_emails or "").strip(),
        "AWS_REGION": env_values["AWS_REGION"],
        "ARTIFACT_BUCKET": env_values["ARTIFACT_BUCKET"],
        "CLIENT_AWS_ROLE_ARN": env_values["CLIENT_AWS_ROLE_ARN"],
        "NONPROD_AWS_ROLE_ARN": env_values["NONPROD_AWS_ROLE_ARN"],
        "TARGET_AWS_ROLE_ARN": env_values["TARGET_AWS_ROLE_ARN"],
        "IAM_VALIDATION_MODE": env_values["IAM_VALIDATION_MODE"],
        "EKS_ACCESS_MODE": env_values["EKS_ACCESS_MODE"],
        "ENABLE_NOTIFICATIONS": str(notification_requested).lower(),
        "SNS_TOPIC_ARN": env_values["SNS_TOPIC_ARN"],
    }
    bool_param_names = [
        "ENABLE_SONARQUBE", "ENABLE_CHECKMARX", "ENABLE_SOAPUI", "ENABLE_JMETER",
        "ENABLE_SELENIUM", "ENABLE_NEWMAN", "ENABLE_RESTASSURED", "ENABLE_UFT",
        "ENABLE_TRIVY", "ENABLE_OPA", "ENABLE_NOTIFICATIONS", "NEWMAN_FAIL_ON_ERROR",
    ]
    job_config = build_runner_job_config(
        description=f"Validation Pipeline for {values['PROJECT_NAME']}",
        values=values,
        bool_param_names=bool_param_names,
    )

    job_url = f"{JENKINS_URL}/job/{job_name}/api/json"
    job_check = requests.get(job_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    if job_check.status_code == 200:
        config_response = jenkins_post(f"{JENKINS_URL}/job/{job_name}/config.xml", content_type="application/xml", data=job_config)
        create_status = "updated"
        create_response_code = config_response.status_code
        create_response_obj = config_response
    else:
        create_response = jenkins_post(f"{JENKINS_URL}/createItem?name={job_name}", content_type="application/xml", data=job_config)
        create_status = "created"
        create_response_code = create_response.status_code
        create_response_obj = create_response

    if create_response_code not in (200, 201, 202):
        return jenkins_failure_response(f"{create_status} job '{job_name}'", create_response_obj)

    build_response = trigger_jenkins_parameterized_build(job_name, values)
    if build_response.status_code not in (200, 201, 202):
        return jenkins_failure_response(f"trigger build for job '{job_name}'", build_response)

    ensure_application_registered(
        db,
        name=request.project_name.strip(),
        owner_email=principal_email(principal),
        repo_url=request.repo_url.strip(),
        branch=request.branch.strip() or "main",
        app_type=request.project_type,
    )

    usage_report = report_license_usage(
        validated_license,
        "pipeline.validation.requested",
        metadata={
            "pipeline_kind": "TEST_DEVOPS",
            "project_name": request.project_name.strip(),
            "project_type": request.project_type,
            "target_env": env_values["TARGET_ENV"],
            "branch": request.branch.strip() or "main",
            "repo_type": request.repo_type,
            "jenkins_job": job_name,
            "requester_hash": _usage_requester_hash(principal_email(principal)),
            "validation_gates": {
                "ui_end_to_end": bool(request.ENABLE_SELENIUM),
                "api_regression": bool(request.ENABLE_NEWMAN),
                "performance": bool(request.ENABLE_JMETER),
                "code_quality": bool(request.ENABLE_SONARQUBE),
                "static_security": bool(request.ENABLE_CHECKMARX),
                "container_iac_vulnerability": bool(request.ENABLE_TRIVY),
                "policy_validation": bool(request.ENABLE_OPA),
            },
        },
    )

    return {
        "status": f"Test Devops pipeline {create_status} and triggered",
        "project_name": request.project_name.strip(),
        "jenkins_job": job_name,
        "project_type": request.project_type,
        "license": license_summary(validated_license),
        "usage_report": usage_report,
        "environment_preflight": sanitize_preflight_for_principal(preflight, principal),
        "create_response_code": create_response_code,
        "build_response_code": build_response.status_code,
    }

@app.post("/prod/devops/pipeline")
def create_prod_devops_pipeline(
    request: ProdDevopsPipelineRequest,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN, ROLE_RELEASE_MANAGER)),
):
    if not request.project_name.strip():
        return JSONResponse(status_code=400, content={"error": "project_name is required"})
    project_name = request.project_name.strip()
    source_env = normalize_environment_name(request.source_env)
    target_env = normalize_environment_name(request.target_env)
    if source_env == target_env:
        return JSONResponse(
            status_code=400,
            content={"error": "Source and target environments must be different for release promotion"},
        )
    if source_env not in {"DEV", "QA", "STAGE"}:
        return JSONResponse(
            status_code=400,
            content={"error": "Release promotion source must be DEV, QA, or STAGE"},
        )
    if target_env not in {"QA", "STAGE", "PROD"}:
        return JSONResponse(
            status_code=400,
            content={"error": "Release promotion target must be QA, STAGE, or PROD"},
        )
    job_name = f"{project_name}-{target_env.lower()}-release"

    source_env_values, source_env_error = resolve_environment_catalog_values(db, source_env, project_name, request)
    if source_env_error:
        return JSONResponse(status_code=400, content={"error": source_env_error, "status": "source_environment_catalog_missing"})
    target_env_values, target_env_error = resolve_environment_catalog_values(db, target_env, project_name, request)
    if target_env_error:
        return JSONResponse(status_code=400, content={"error": target_env_error, "status": "target_environment_catalog_missing"})
    require_environment_permission(principal, target_env_values["TARGET_ENV"], "Release Promotion Pipeline")

    missing_catalog_fields = [
        field for field in ["ARTIFACT_BUCKET", "ECR_REGISTRY", "ECR_REPOSITORY", "SOURCE_AWS_ROLE_ARN"]
        if not source_env_values.get(field)
    ]
    target_cluster_field = f"{target_env}_CLUSTER_NAME"
    missing_catalog_fields += [
        field for field in ["ECR_REGISTRY", "ECR_REPOSITORY", "TARGET_AWS_ROLE_ARN", target_cluster_field]
        if not target_env_values.get(field)
    ]
    if missing_catalog_fields:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Environment Catalog is missing required release promotion settings.",
                "missing_fields": sorted(set(missing_catalog_fields)),
                "source_env": source_env_values["TARGET_ENV"],
                "target_env": target_env_values["TARGET_ENV"],
            },
        )

    source_preflight = run_environment_preflight(db, source_env, project_name, request, pipeline_kind="PROD_DEVOPS_SOURCE")
    target_preflight = run_environment_preflight(db, target_env, project_name, request, pipeline_kind="PROD_DEVOPS")
    if ENVIRONMENT_PREFLIGHT_ENFORCED and (not source_preflight.get("ready") or not target_preflight.get("ready")):
        return JSONResponse(
            status_code=400,
            content={
                "error": "Source or target environment is not ready for release promotion.",
                "status": "environment_not_ready",
                "preflight": {
                    "source": sanitize_preflight_for_principal(source_preflight, principal),
                    "target": sanitize_preflight_for_principal(target_preflight, principal),
                },
            },
        )

    license_doc = merge_request_license(request.dict())
    try:
        validated_license = validate_license(
            license_doc,
            pipeline_name="Release Promotion Pipeline",
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
    requester = principal.username or request.requestedBy
    requester_notify_email = (request.notify_email or "").strip() or principal_email(principal)
    notification_requested = bool(
        request.enable_notifications or
        requester_notify_email or
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
        "PROJECT_NAME": project_name,
        "PIPELINE_KIND": "PROD_DEVOPS",
        "SERVICE_NAME": "Release Promotion Pipeline",
        "REQUESTED_BY": requester,
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
        "TARGET_IMAGE_TAG": (request.target_image_tag or "").strip(),
        "CLIENT_AWS_ROLE_ARN": (request.client_aws_role_arn or target_env_values["CLIENT_AWS_ROLE_ARN"] or source_env_values["CLIENT_AWS_ROLE_ARN"]).strip(),
        "SOURCE_AWS_ROLE_ARN": (request.source_aws_role_arn or source_env_values["SOURCE_AWS_ROLE_ARN"] or source_env_values["CLIENT_AWS_ROLE_ARN"]).strip(),
        "TARGET_AWS_ROLE_ARN": (request.target_aws_role_arn or target_env_values["TARGET_AWS_ROLE_ARN"] or target_env_values["CLIENT_AWS_ROLE_ARN"]).strip(),
        "DEV_CLUSTER_NAME": source_env_values["DEV_CLUSTER_NAME"] or target_env_values["DEV_CLUSTER_NAME"],
        "QA_CLUSTER_NAME": source_env_values["QA_CLUSTER_NAME"] or target_env_values["QA_CLUSTER_NAME"],
        "STAGE_CLUSTER_NAME": source_env_values["STAGE_CLUSTER_NAME"] or target_env_values["STAGE_CLUSTER_NAME"],
        "PROD_CLUSTER_NAME": target_env_values["PROD_CLUSTER_NAME"],
        "NAMESPACE_STRATEGY": target_env_values["NAMESPACE_STRATEGY"],
        "IAM_VALIDATION_MODE": target_env_values["IAM_VALIDATION_MODE"],
        "EKS_ACCESS_MODE": target_env_values["EKS_ACCESS_MODE"],
        "APP_NAMESPACE": target_env_values["APP_NAMESPACE"],
        "DEV_NAMESPACE": source_env_values["DEV_NAMESPACE"] or target_env_values["DEV_NAMESPACE"],
        "QA_NAMESPACE": source_env_values["QA_NAMESPACE"] or target_env_values["QA_NAMESPACE"],
        "STAGE_NAMESPACE": source_env_values["STAGE_NAMESPACE"] or target_env_values["STAGE_NAMESPACE"],
        "PROD_NAMESPACE": target_env_values["PROD_NAMESPACE"],
        "SECRET_ENABLED": str(request.secret_enabled).lower(),
        "XID_ARRAY": (request.xid_array or "").strip(),
        "APPROVER": (request.approver or "").strip(),
        "REQUIRE_APPROVAL": str(request.require_approval or target_env == "PROD").lower(),
        "NOTIFY_EMAIL": requester_notify_email,
        "NOTIFY_CC": (request.additional_notify_emails or "").strip(),
        "ENABLE_NOTIFICATIONS": str(notification_requested).lower(),
        "SNS_TOPIC_ARN": target_env_values["SNS_TOPIC_ARN"] or source_env_values["SNS_TOPIC_ARN"] or (request.sns_topic_arn or "").strip(),
    }
    bool_param_names = ["SECRET_ENABLED", "REQUIRE_APPROVAL", "ENABLE_NOTIFICATIONS"]
    job_config = build_runner_job_config(
        description=f"Release Promotion Pipeline for {values['PROJECT_NAME']}",
        values=values,
        bool_param_names=bool_param_names,
    )

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
        create_response_obj = config_response
    else:
        create_response = jenkins_post(
            f"{JENKINS_URL}/createItem?name={job_name}",
            content_type="application/xml",
            data=job_config,
        )
        create_status = "created"
        create_response_code = create_response.status_code
        create_response_obj = create_response

    if create_response_code not in (200, 201, 202):
        return jenkins_failure_response(f"{create_status} job '{job_name}'", create_response_obj)

    build_response = trigger_jenkins_parameterized_build(job_name, values)
    if build_response.status_code not in (200, 201, 202):
        return jenkins_failure_response(f"trigger build for job '{job_name}'", build_response)

    usage_report = report_license_usage(
        validated_license,
        "pipeline.release_promotion.requested",
        metadata={
            "pipeline_kind": "PROD_DEVOPS",
            "project_name": project_name,
            "source_env": source_env_values["TARGET_ENV"],
            "target_env": target_env_values["TARGET_ENV"],
            "source_image_tag": values["SOURCE_IMAGE_TAG"],
            "target_image_tag": values["TARGET_IMAGE_TAG"],
            "artifact_prefix": artifact_prefix,
            "target_namespace": target_env_values["APP_NAMESPACE"],
            "jenkins_job": job_name,
            "requester_hash": _usage_requester_hash(principal_email(principal)),
            "approval_required": bool(request.require_approval or target_env == "PROD"),
        },
    )

    return {
        "status": f"Release promotion pipeline {create_status} and triggered",
        "project_name": project_name,
        "job_name": job_name,
        "license": license_summary_doc,
        "usage_report": usage_report,
        "environment_preflight": {
            "source": sanitize_preflight_for_principal(source_preflight, principal),
            "target": sanitize_preflight_for_principal(target_preflight, principal),
        },
        "create_response_code": create_response_code,
        "build_response_code": build_response.status_code,
    }

@app.post("/pipeline/trigger")
def trigger_existing_pipeline(
    request: TriggerRequest,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN, ROLE_DEVELOPER, ROLE_QA, ROLE_RELEASE_MANAGER)),
):
    job_url = f"{JENKINS_URL}/job/{request.project_name}/api/json"
    job_check = requests.get(job_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    if job_check.status_code != 200:
        return {"status": "Job not found", "message": f"Pipeline '{request.project_name}' does not exist."}
    build_url = f"{JENKINS_URL}/job/{request.project_name}/build"
    build_trigger = requests.post(build_url, headers=jenkins_headers(), auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    return {"status": "Build triggered", "project_name": request.project_name, "code": build_trigger.status_code}

@app.get("/pipeline/logs/{job_name}/{build_number}")
def get_console_logs(
    job_name: str,
    build_number: int,
    principal: AuthPrincipal = Depends(get_current_principal),
):
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
    email: Optional[str] = None,
    application: Optional[str] = None,
    source: Optional[str] = None,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(get_current_principal),
):
    query = authorized_vulnerability_query(db, principal)

    if application:
        app_entry = db.query(Application).filter_by(name=application).first()
        if app_entry:
            query = query.filter(Vulnerability.application_id == app_entry.id)
        else:
            return []

    if source:
        query = query.filter_by(source=source)

    results = query.order_by(Vulnerability.timestamp.desc()).all()

    return [serialize_security_finding(v) for v in results]

@app.get("/security/findings")
def get_security_findings(
    email: Optional[str] = None,
    application: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(get_current_principal),
):
    query = authorized_vulnerability_query(db, principal)
    if application:
        app_entry = db.query(Application).filter_by(name=application).first()
        if not app_entry:
            return []
        query = query.filter(Vulnerability.application_id == app_entry.id)
    findings = [serialize_security_finding(v) for v in query.order_by(Vulnerability.timestamp.desc()).all()]
    if category:
        findings = [f for f in findings if f.get("category") == category]
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.upper()]
    return findings

@app.delete("/vulnerabilities/clear")
def clear_vulnerabilities(
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
):
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

CONTAINER_TARGET_MARKERS = (
    "(alpine",
    "(amazon",
    "(centos",
    "(debian",
    "(oracle",
    "(redhat",
    "(rocky",
    "(ubuntu",
    "(wolfi",
)

DEPENDENCY_TARGET_MARKERS = (
    "package-lock.json",
    "package.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "build.gradle",
    "requirements.txt",
    "poetry.lock",
    "pipfile.lock",
    "go.mod",
    "composer.lock",
    "gemfile.lock",
)

def looks_like_container_target(target: Optional[str]) -> bool:
    target_value = (target or "").strip().lower()
    if not target_value:
        return False
    if any(marker in target_value for marker in DEPENDENCY_TARGET_MARKERS):
        return False
    return any(marker in target_value for marker in CONTAINER_TARGET_MARKERS)

def normalize_security_category(
    source: Optional[str],
    package_name: Optional[str],
    vulnerability_id: Optional[str],
    target: Optional[str] = None,
) -> str:
    source_key = (source or "").strip().upper()
    if source_key == "DEPENDENCY VULNERABILITY" and looks_like_container_target(target):
        return "Container Vulnerability"
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
    category = normalize_security_category(v.source, v.package_name, v.vulnerability_id, v.target)
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
        "policy_bundle": v.policy_bundle,
        "policy_version": v.policy_version,
        "policy_ref": v.policy_ref,
        "policy_decision": v.policy_decision,
        "waiver_status": v.waiver_status,
        "waiver_expiry": v.waiver_expiry,
        "waiver_reason": v.waiver_reason,
        "waiver_approved_by": v.waiver_approved_by,
        "evidence_uri": v.evidence_uri,
        "traceability": {
            "jenkins_job": v.jenkins_job,
            "build_number": v.build_number,
            "jenkins_url": v.jenkins_url,
            "evidence_uri": v.evidence_uri,
        },
    }
    
@app.post("/register_application")
def register_application(
    request: RegisterAppRequest,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN, ROLE_DEVELOPER)),
):
    app_entry = db.query(Application).filter_by(name=request.name).first()
    if app_entry:
        return JSONResponse(status_code=400, content={"error": "Application already exists"})
    owner_email = request.owner_email if principal_has_role(principal, CATALOG_ADMIN_ROLES) else principal_email(principal)
    app_entry = Application(name=request.name, description=request.description, owner_email=owner_email, repo_url=request.repo_url, branch=request.branch)
    db.add(app_entry)
    db.commit()
    db.refresh(app_entry)
    db.add(ApplicationUserAccess(user_email=owner_email, application_id=app_entry.id))
    db.commit()
    return {"status": "registered", "application_id": app_entry.id}

@app.post("/grant_access")
def grant_access(
    request: GrantAccessRequest,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(get_current_principal),
):
    app_entry = db.query(Application).filter_by(name=request.application).first()
    if not app_entry:
        return JSONResponse(status_code=404, content={"error": "Application not found"})
    if not principal_has_role(principal, CATALOG_ADMIN_ROLES) and app_entry.owner_email != principal_email(principal):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only platform admins or application owners can grant application access.",
        )
    existing_access = db.query(ApplicationUserAccess).filter_by(
        user_email=request.user_email,
        application_id=app_entry.id,
    ).first()
    if not existing_access:
        db.add(ApplicationUserAccess(user_email=request.user_email, application_id=app_entry.id))
        db.commit()
    return {"status": "access granted"}

@app.post("/upload_vulnerabilities")
def upload_vulnerabilities(payload: UploadPayload, db: Session = Depends(get_db)):
    try:
        repo_url = (payload.repo_url or "N/A").strip()
        app_entry = db.query(Application).filter_by(name=payload.application).first()
        if not app_entry and repo_url and repo_url != "N/A":
            app_entry = db.query(Application).filter_by(repo_url=repo_url).first()
            if app_entry:
                app_entry.name = payload.application or app_entry.name
                app_entry.owner_email = payload.requestedBy or app_entry.owner_email

        if not app_entry:
            app_entry = Application(
                name=payload.application,
                description="Auto-created",
                owner_email=payload.requestedBy or "unknown@horizonrelevance.com",
                repo_url=repo_url
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
                source=normalize_security_category(v.source, v.package_name, v.vulnerability_id, v.target),
                timestamp=datetime.utcnow(),
                line=v.line,
                rule=v.rule,
                status=v.status,
                predicted_severity=v.predictedSeverity,
                jenkins_job=payload.jenkins_job,
                build_number=payload.build_number,
                jenkins_url=payload.jenkins_url,
                policy_bundle=v.policy_bundle,
                policy_version=v.policy_version,
                policy_ref=v.policy_ref,
                policy_decision=v.policy_decision,
                waiver_status=v.waiver_status,
                waiver_expiry=v.waiver_expiry,
                waiver_reason=v.waiver_reason,
                waiver_approved_by=v.waiver_approved_by,
                evidence_uri=v.evidence_uri,
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

        response = jenkins_post(
            jenkins_url,
            content_type="application/x-www-form-urlencoded",
            data=params,
        )

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
