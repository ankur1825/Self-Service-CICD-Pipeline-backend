from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List
import os
import requests
from ldap3 import Server, Connection, ALL, SUBTREE

app = FastAPI(root_path="/pipeline/api")

# Jenkins configuration
JENKINS_URL = "https://horizonrelevance.com/jenkins"
JENKINS_USER = os.getenv("JENKINS_USER")
JENKINS_TOKEN = os.getenv("JENKINS_TOKEN")

# LDAP configuration (JumpCloud)
LDAP_SERVER = "ldaps://ldap.jumpcloud.com:636"
LDAP_USER = "uid=ankur.kashyap,ou=Users,o=6817d9a0d50cd4b1b5b81ba7,dc=jumpcloud,dc=com"
LDAP_PASSWORD = os.getenv("LDAP_MANAGER_PASSWORD")
LDAP_BASE_DN = "ou=Users,o=6817d9a0d50cd4b1b5b81ba7,dc=jumpcloud,dc=com"
SEARCH_FILTER = "(objectClass=person)"

# CORS setup for frontend
origins = [
    "https://horizonrelevance.com/pipeline"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------- LDAP LOGIN ENDPOINT -----------
@app.post("/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username")
    password = body.get("password")

    if not username or not password:
        return JSONResponse(status_code=400, content={"error": "Username and password required"})

    try:
        server = Server(LDAP_SERVER, get_info=ALL)

        # 1. Use manager DN to find full DN of the user
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

        # 2. Try binding with user DN and provided password
        auth_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        auth_conn.unbind()

        # 3. Return user info on successful bind
        return {
            "username": username,
            "fullName": display_name,
            "email": email
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=401, content={"error": "Invalid credentials or server error"})

# ----------- LDAP USER FETCH ENDPOINT -----------
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
            uid = str(entry.uid) if "uid" in entry else None
            display_name = str(entry.displayName) if "displayName" in entry else uid
            email = str(entry.mail) if "mail" in entry else ""

            if uid and uid not in seen:
                users.append({
                    "username": uid,
                    "fullName": display_name,
                    "email": email
                })
                seen.add(uid)

        conn.unbind()
        return JSONResponse(content=users)

    except Exception as e:
        print("LDAP error:", e)
        return JSONResponse(status_code=500, content={"error": "Failed to fetch LDAP users"})


# ----------- PIPELINE REQUEST MODEL -----------
class PipelineRequest(BaseModel):
    project_name: str
    app_type: str
    repo_url: str
    branch: str
    ENABLE_SONARQUBE: bool
    ENABLE_OPA: bool
    requestedBy: str


# ----------- PIPELINE CREATION ENDPOINT -----------
@app.post("/pipeline")
def create_pipeline(request: PipelineRequest):
    print("Received pipeline request:", request.dict())

    jenkinsfile_template = f"""
    @Library('jenkins-shared-library@main') _
    pipeline {{
        agent any
        stages {{
            stage('Clone Repository') {{
                steps {{
                    git credentialsId: 'github-token', url: '{request.repo_url}', branch: '{request.branch}'
                }}
            }}
            stage('Check Repository') {{
                steps {{
                    script {{
                        sh 'pwd'
                        sh 'ls -lrth'    
                    }}
                }}
            }}
            stage('Load Application Pipeline') {{
                steps {{
                    script {{
                        main_template(APP_TYPE: '{request.app_type}', 
                                      REPO_URL: '{request.repo_url}', 
                                      BRANCH: '{request.branch}', 
                                      CREDENTIALS_ID: 'github-token', 
                                      ENABLE_SONARQUBE: '{str(request.ENABLE_SONARQUBE).lower()}', 
                                      ENABLE_OPA: '{str(request.ENABLE_OPA).lower()}')
                    }}
                }}
            }}
        }}
    }}
    """

    job_config = f"""
    <flow-definition plugin="workflow-job">
        <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
            <script>{jenkinsfile_template}</script>
            <sandbox>true</sandbox>
        </definition>
    </flow-definition>
    """

    # Jenkins job creation
    create_response = requests.post(
        f"{JENKINS_URL}/createItem?name={request.project_name}",
        headers={"Content-Type": "application/xml"},
        auth=(JENKINS_USER, JENKINS_TOKEN),
        data=job_config,
        verify=False
    )
    print("Jenkins Create Response:", create_response.status_code, create_response.text)

    if create_response.status_code not in [200, 201]:
        return {
            "status": "Failed to create pipeline",
            "create_response_code": create_response.status_code,
            "jenkins_response": create_response.text
        }

    # Jenkins build trigger
    build_response = requests.post(
        f"{JENKINS_URL}/job/{request.project_name}/build",
        auth=(JENKINS_USER, JENKINS_TOKEN),
        verify=False
    )
    print("Jenkins Build Trigger Response:", build_response.status_code, build_response.text)

    return {
        "status": "Pipeline created and triggered",
        "create_response_code": create_response.status_code,
        "build_response_code": build_response.status_code
    }


# ----------- PIPELINE LOG FETCH ENDPOINT -----------
@app.get("/pipeline/logs/{job_name}/{build_number}")
def get_console_logs(job_name: str, build_number: int):
    log_url = f"{JENKINS_URL}/job/{job_name}/{build_number}/logText/progressiveText"
    response = requests.get(log_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)

    return {
        "build_number": build_number,
        "job_name": job_name,
        "logs": response.text
    }
