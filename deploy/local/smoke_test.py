#!/usr/bin/env python3
import json
import sys
import time
import urllib.error
import urllib.request


BASE_URL = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8080/pipeline/api"
PASSWORD = "MigrationTest!2026"


def request(path, method="GET", payload=None, token=None, expected=(200,)):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            result = json.loads(response.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        status = exc.code
        result = json.loads(exc.read().decode() or "{}")
    if status not in expected:
        raise AssertionError(f"{method} {path}: expected {expected}, received {status}: {result}")
    return result


def login(username):
    result = request("/login", "POST", {"username": username, "password": PASSWORD})
    if not result.get("token"):
        raise AssertionError(f"Login did not return a token for {username}")
    return result


def wait_until_ready():
    health_url = f"{BASE_URL}/health/ready"
    for _ in range(60):
        try:
            with urllib.request.urlopen(health_url, timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(2)
    raise TimeoutError(f"Backend did not become ready at {health_url}")


def main():
    wait_until_ready()
    admin = login("migration-admin")
    approver = login("migration-approver")
    auditor = login("migration-auditor")

    capabilities = request("/cloud-migration/capabilities", token=admin["token"])
    assert capabilities["licensed"] is True
    aws = next(provider for provider in capabilities["providers"] if provider["provider"] == "aws")
    assert aws["execution_enabled"] is False
    assert capabilities["data_boundary"] == "client-hosted"

    catalog = request("/environment-catalog", token=admin["token"])
    assert any(item["name"] == "DEV" for item in catalog["environments"])

    suffix = str(int(time.time()))
    project = request(
        "/cloud-migration/projects",
        "POST",
        {
            "name": f"Local rehost {suffix}",
            "description": "Automated local acceptance test",
            "source_type": "aws-ec2",
            "target_provider": "aws",
            "target_environment": "DEV",
        },
        admin["token"],
        expected=(201,),
    )
    wave = request(
        f"/cloud-migration/projects/{project['id']}/waves",
        "POST",
        {
            "name": "Wave 1",
            "migration_method": "mgn",
            "source_region": "us-west-2",
            "workloads": [{"source_ref": "s-local-mgn-source-001", "os_family": "LINUX"}],
        },
        admin["token"],
        expected=(201,),
    )
    planned = request(
        f"/cloud-migration/waves/{wave['id']}/plan",
        "POST",
        {"expected_version": 0},
        admin["token"],
    )
    assert planned["status"] == "PLANNED"
    assert planned["plan"]["execution_enabled"] is False

    request(
        f"/cloud-migration/waves/{wave['id']}/approve",
        "POST",
        {"expected_version": planned["plan_version"], "comment": "self approval must fail"},
        admin["token"],
        expected=(409,),
    )
    approved = request(
        f"/cloud-migration/waves/{wave['id']}/approve",
        "POST",
        {"expected_version": planned["plan_version"], "comment": "Local acceptance approval"},
        approver["token"],
    )
    assert approved["status"] == "APPROVED"

    audit = request("/cloud-migration/audit-events?limit=100", token=auditor["token"])
    event_types = {event["event_type"] for event in audit["events"]}
    assert {"PROJECT_CREATED", "WAVE_CREATED", "WAVE_PLANNED", "WAVE_APPROVED"}.issubset(event_types)
    print("PASS: licensed client-hosted project/wave/plan/separate-approval/audit workflow")
    print("PASS: AWS execution is disabled")


if __name__ == "__main__":
    main()
