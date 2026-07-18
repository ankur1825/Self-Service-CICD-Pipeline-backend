#!/usr/bin/env python3
"""Authenticated EKS mock acceptance; prints no credentials or session tokens."""

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request


BASE_URL = os.getenv("ACCEPTANCE_BASE_URL", "http://127.0.0.1:8000")
TARGET_ENVIRONMENT = os.getenv("ACCEPTANCE_TARGET_ENV", "DEV")
SESSION_SECRET = os.environ["BACKEND_SESSION_SECRET"]


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def token(username: str, role: str) -> str:
    now = int(time.time())
    claims = {
        "sub": username,
        "email": f"{username}@client.example",
        "full_name": username.replace("-", " ").title(),
        "roles": [role],
        "groups": [],
        "iat": now,
        "exp": now + 1800,
    }
    payload = b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signature = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{b64url(signature)}"


AUTHOR = token("mock-architect", "migration-architect")
AUTHOR_APPROVER = token("mock-architect", "platform-admin")
APPROVER = token("mock-approver", "migration-approver")
AUDITOR = token("mock-auditor", "migration-auditor")


def call(method: str, path: str, bearer: str, body=None, headers=None, expected_error=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
            **(headers or {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode())
            if expected_error is not None:
                raise AssertionError(f"Expected HTTP {expected_error} from {path}; request succeeded.")
            return payload
    except urllib.error.HTTPError as exc:
        payload = json.loads(exc.read().decode())
        if expected_error == exc.code:
            return payload
        raise AssertionError(f"{method} {path} failed with HTTP {exc.code}: {payload}") from exc


def wait_job(job_id: str, timeout: int = 60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = call("GET", f"/cloud-migration/jobs/{job_id}", AUDITOR)
        if job["status"] in {"SUCCEEDED", "FAILED"}:
            assert job["status"] == "SUCCEEDED", job
            assert job["result"]["mock"] is True, job["result"]
            assert job["result"]["execution_mode"] == "mock", job["result"]
            return job
        time.sleep(1)
    raise AssertionError(f"Job {job_id} did not finish within {timeout} seconds.")


def wave_from_project(project_id: str, wave_id: str):
    project = call("GET", f"/cloud-migration/projects/{project_id}", AUDITOR)
    return next(item for item in project["waves"] if item["id"] == wave_id)


def create_approved_wave(project_id: str, name: str, source_ref: str):
    wave = call(
        "POST",
        f"/cloud-migration/projects/{project_id}/waves",
        AUTHOR,
        {
            "name": name,
            "migration_method": "mgn",
            "workloads": [{"source_ref": source_ref, "os_family": "LINUX"}],
        },
    )
    planned = call(
        "POST",
        f"/cloud-migration/waves/{wave['id']}/plan",
        AUTHOR,
        {"expected_version": wave["plan_version"]},
    )
    assert planned["plan"]["blocking_issue_count"] == 0, planned["plan"]
    approved = call(
        "POST",
        f"/cloud-migration/waves/{wave['id']}/approve",
        APPROVER,
        {"expected_version": planned["plan_version"], "comment": "MOCK-ACCEPTANCE-CAB"},
    )
    assert approved["status"] == "APPROVED", approved
    return approved


def execute(wave, action: str, sequence: int, expect_separation_check: bool = False):
    key = f"eks-mock:{action}:{sequence:04d}:{wave['id']}"
    body = {
        "tcp1500_hosts": ["mock-replication.client.local"] if action == "preflight" else [],
        "terminate_instances": True,
        "rollback_to": "ready-for-test",
    }
    requested = call(
        "POST",
        f"/cloud-migration/waves/{wave['id']}/jobs/{action}",
        AUTHOR,
        body,
        {"Idempotency-Key": key},
    )
    replayed = call(
        "POST",
        f"/cloud-migration/waves/{wave['id']}/jobs/{action}",
        AUTHOR,
        body,
        {"Idempotency-Key": key},
    )
    assert replayed["id"] == requested["id"], "Idempotency replay created another job."

    if requested["status"] == "AWAITING_APPROVAL":
        confirmation = f"{requested['action']} {wave['id']}"
        if expect_separation_check:
            call(
                "POST",
                f"/cloud-migration/jobs/{requested['id']}/approve",
                AUTHOR_APPROVER,
                {
                    "expected_version": requested["version"],
                    "confirmation": confirmation,
                    "comment": "Self approval must fail",
                },
                expected_error=409,
            )
            call(
                "POST",
                f"/cloud-migration/waves/{wave['id']}/jobs/{action}",
                AUTHOR,
                body,
                {"Idempotency-Key": key + ":other"},
                expected_error=409,
            )
        approved = call(
            "POST",
            f"/cloud-migration/jobs/{requested['id']}/approve",
            APPROVER,
            {
                "expected_version": requested["version"],
                "confirmation": confirmation,
                "comment": f"MOCK-ACTION-CAB-{sequence:04d}",
            },
        )
        assert approved["status"] == "QUEUED", approved
    return wait_job(requested["id"])


def verify_evidence(jobs):
    evidence_count = 0
    for job in jobs:
        assert job["evidence"], job
        for summary in job["evidence"]:
            artifact = call("GET", f"/cloud-migration/evidence/{summary['id']}", AUDITOR)
            assert artifact["integrity_verified"] is True, artifact
            assert artifact["content_sha256"] == summary["content_sha256"], artifact
            assert artifact["payload"]["payload"]["mock"] is True, artifact
            evidence_count += 1
    return evidence_count


def main():
    stamp = str(int(time.time()))
    capabilities = call("GET", "/cloud-migration/capabilities", AUDITOR)
    aws = capabilities["providers"][0]
    assert capabilities["licensed"] is True, capabilities
    assert aws["execution_worker"]["mode"] == "mock", aws
    assert aws["execution_worker"]["mock_execution_enabled"] is True, aws

    health = call("GET", "/cloud-migration/execution/health", AUDITOR)
    assert health["status"] == "healthy", health
    assert health["live_worker_count"] >= 1, health

    project = call(
        "POST",
        "/cloud-migration/projects",
        AUTHOR,
        {
            "name": f"EKS mock acceptance {stamp}",
            "description": "Automated happy-path and rollback acceptance; no AWS calls.",
            "source_type": "onprem-vmware",
            "target_provider": "aws",
            "target_environment": TARGET_ENVIRONMENT,
        },
    )

    happy = create_approved_wave(project["id"], "Happy path", f"mock-happy-{stamp}")
    happy_jobs = [
        execute(happy, "preflight", 1),
        execute(happy, "reconcile", 2),
        execute(happy, "start-test", 3, expect_separation_check=True),
        execute(happy, "finalize-test", 4),
        execute(happy, "start-cutover", 5),
        execute(happy, "finalize-cutover", 6),
    ]
    happy_state = wave_from_project(project["id"], happy["id"])
    assert happy_state["status"] == "FINALIZED", happy_state
    assert all(item["status"] == "CUTOVER_COMPLETE" for item in happy_state["workloads"]), happy_state

    rollback = create_approved_wave(project["id"], "Rollback path", f"mock-rollback-{stamp}")
    rollback_jobs = [
        execute(rollback, "reconcile", 101),
        execute(rollback, "start-test", 102),
        execute(rollback, "rollback", 103),
    ]
    rollback_state = wave_from_project(project["id"], rollback["id"])
    assert rollback_state["status"] == "TEST_READY", rollback_state
    assert all(item["status"] == "TEST_READY" for item in rollback_state["workloads"]), rollback_state

    evidence_count = verify_evidence(happy_jobs + rollback_jobs)
    deadline = time.time() + 45
    while time.time() < deadline:
        health = call("GET", "/cloud-migration/execution/health", AUDITOR)
        if health["active_job_count"] == 0:
            break
        time.sleep(2)
    assert health["active_job_count"] == 0, health
    assert health["status"] == "healthy", health
    assert health["expired_lease_count"] == 0, health

    print(json.dumps({
        "acceptance": "PASS",
        "execution_mode": health["execution_mode"],
        "project_id": project["id"],
        "happy_wave_status": happy_state["status"],
        "rollback_wave_status": rollback_state["status"],
        "jobs_verified": len(happy_jobs) + len(rollback_jobs),
        "evidence_verified": evidence_count,
        "live_workers": health["live_worker_count"],
        "expired_leases": health["expired_lease_count"],
        "active_jobs": health["active_job_count"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
