from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import os
import requests
from ldap3 import Server, Connection, ALL, SUBTREE

from models import Application, ApplicationUserAccess, Vulnerability, Base
from database import SessionLocal, engine

app = FastAPI(root_path="/pipeline/api")

# Jenkins configuration
JENKINS_URL = "https://horizonrelevance.com/jenkins"
JENKINS_USER = os.getenv("JENKINS_USER")
JENKINS_TOKEN = os.getenv("JENKINS_TOKEN")

# LDAP configuration
LDAP_SERVER = "ldaps://ldap.jumpcloud.com:636"
LDAP_USER = "uid=ankur.kashyap,ou=Users,o=6817d9a0d50cd4b1b5b81ba7,dc=jumpcloud,dc=com"
LDAP_PASSWORD = os.getenv("LDAP_MANAGER_PASSWORD")
LDAP_BASE_DN = "ou=Users,o=6817d9a0d50cd4b1b5b81ba7,dc=jumpcloud,dc=com"
SEARCH_FILTER = "(objectClass=person)"

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

class VulnerabilityUpload(BaseModel):
    vulnerabilities: List[VulnerabilityModel]

class OPARiskModel(BaseModel):
    target: str
    violation: str
    severity: str
    risk_score: float

class OPARiskUpload(BaseModel):
    risks: List[OPARiskModel]

class UploadPayload(BaseModel):
    application: str
    vulnerabilities: List[VulnerabilityModel]

class RegisterAppRequest(BaseModel):
    name: str
    description: Optional[str] = None
    owner_email: str

class GrantAccessRequest(BaseModel):
    user_email: str
    application: str    

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
            search_filter=f"(uid={username})",
            search_scope=SUBTREE,
            attributes=["displayName", "mail", "uid"]
        )
        if not search_conn.entries:
            return JSONResponse(status_code=401, content={"error": "User not found"})

        user_entry = search_conn.entries[0]
        user_dn = str(user_entry.entry_dn)
        display_name = str(user_entry.displayName)
        email = str(user_entry.mail)
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
            attributes=["uid", "displayName", "mail"]
        )
        users = []
        seen = set()
        for entry in conn.entries:
            uid = str(entry.uid)
            display_name = str(entry.displayName)
            email = str(entry.mail)
            if uid not in seen:
                users.append({"username": uid, "fullName": display_name, "email": email})
                seen.add(uid)
        conn.unbind()
        return JSONResponse(content=users)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Failed to fetch LDAP users"})

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

vulnerabilities_store = []

@app.post("/vulnerabilities")
async def upload_vulnerabilities(payload: VulnerabilityUpload):
    from datetime import datetime
    for vuln in payload.vulnerabilities:
        if not vuln.timestamp:
            vuln.timestamp = datetime.utcnow().isoformat()
        vulnerabilities_store.append(vuln.dict())
    return {"status": "success", "received_count": len(payload.vulnerabilities)}

@app.get("/vulnerabilities")
async def get_vulnerabilities(source: Optional[str] = None):
    return [v for v in vulnerabilities_store if v.get("source") == source] if source else vulnerabilities_store

@app.delete("/vulnerabilities/clear")
def clear_vulnerabilities():
    vulnerabilities_store.clear()
    return {"status": "cleared"}

@app.post("/opa/risks/")
async def upload_opa_risks(payload: OPARiskUpload):
    for risk in payload.risks:
        vuln_dict = {
            "target": risk.target,
            "package_name": "OPA Policy",
            "installed_version": "N/A",
            "vulnerability_id": risk.violation,
            "severity": risk.severity,
            "fixed_version": get_dynamic_fix(risk.violation),
            "risk_score": risk.risk_score,
            "description": get_dynamic_fix(risk.violation),
            "source": "OPA"
        }
        vulnerabilities_store.append(vuln_dict)
    return {"status": "success", "received_count": len(payload.risks)}

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
    
@app.post("/register_application")
def register_application(request: RegisterAppRequest, db: Session = Depends(get_db)):
    app_entry = db.query(Application).filter_by(name=request.name).first()
    if app_entry:
        return JSONResponse(status_code=400, content={"error": "Application already exists"})
    app_entry = Application(name=request.name, description=request.description, owner_email=request.owner_email)
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
    app_entry = db.query(Application).filter_by(name=payload.application).first()
    if not app_entry:
        return JSONResponse(status_code=404, content={"error": "Application not found"})
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
            predicted_severity=v.predictedSeverity
        )
        db.add(vuln)
        count += 1
    db.commit()
    return {"status": "uploaded", "count": count}    


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