import hashlib
from datetime import datetime
from typing import Any, Dict, List, Sequence

from .aws import AwsExecutionAdapter, AwsExecutionError, MUTATING_ACTIONS, READ_ACTIONS


class MockAwsExecutionAdapter:
    """Deterministic AWS MGN simulator used only by an explicitly enabled test worker."""

    mock = True

    @staticmethod
    def _server_id(source_ref: str) -> str:
        return "s-" + hashlib.sha256(source_ref.encode("utf-8")).hexdigest()[:17]

    @staticmethod
    def _instance_id(source_ref: str) -> str:
        return "i-" + hashlib.sha256((source_ref + ":instance").encode("utf-8")).hexdigest()[:17]

    @staticmethod
    def _workload_status(lifecycle: str, replication: str | None) -> str:
        return AwsExecutionAdapter.workload_status(lifecycle, replication)

    def _servers(self, source_refs: Sequence[str], request: Dict[str, Any]) -> List[Dict[str, Any]]:
        supplied = {
            str(item.get("source_ref") or "").lower(): item
            for item in (request.get("_mock_servers") or [])
            if item.get("source_ref")
        }
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        servers: List[Dict[str, Any]] = []
        for source_ref in source_refs:
            current = supplied.get(str(source_ref).lower()) or {}
            lifecycle = str(current.get("lifecycle_state") or "READY_FOR_TEST")
            replication = str(current.get("replication_state") or "CONTINUOUS")
            servers.append(
                {
                    "source_ref": source_ref,
                    "source_server_id": current.get("source_server_id") or self._server_id(source_ref),
                    "user_provided_id": source_ref,
                    "lifecycle_state": lifecycle,
                    "replication_state": replication,
                    "lag_duration": current.get("lag_duration") or "PT0S",
                    "last_snapshot_date_time": current.get("last_snapshot_date_time") or now,
                    "launched_ec2_instance_id": current.get("launched_ec2_instance_id"),
                    "is_archived": bool(current.get("is_archived", False)),
                    "workload_status": self._workload_status(lifecycle, replication),
                }
            )
        return servers

    @staticmethod
    def _check_lifecycle(action: str, servers: Sequence[Dict[str, Any]]) -> None:
        allowed = {
            "START_TEST": {"READY_FOR_TEST"},
            "FINALIZE_TEST": {"TESTING"},
            "START_CUTOVER": {"READY_FOR_CUTOVER"},
            "ROLLBACK": {"TESTING", "READY_FOR_CUTOVER", "CUTTING_OVER"},
            "FINALIZE_CUTOVER": {"CUTTING_OVER"},
        }.get(action, set())
        invalid = [
            f"{item['source_ref']}={item['lifecycle_state']}"
            for item in servers
            if item.get("lifecycle_state") not in allowed
        ]
        if invalid:
            raise AwsExecutionError(
                f"Mock MGN action {action} is not allowed from the observed lifecycle: {', '.join(invalid)}."
            )

    def execute(
        self,
        *,
        action: str,
        job_id: str,
        wave_id: str,
        region: str,
        expected_account_id: str,
        role_arn: str,
        source_refs: Sequence[str],
        request: Dict[str, Any],
    ) -> Dict[str, Any]:
        normalized = action.strip().upper()
        if normalized not in READ_ACTIONS | MUTATING_ACTIONS:
            raise AwsExecutionError(f"Unsupported mock AWS execution action '{normalized}'.")
        if not source_refs:
            raise AwsExecutionError("The wave has no workload source references.")

        if normalized == "PREFLIGHT":
            hosts = list(dict.fromkeys(request.get("tcp1500_hosts") or ["mock-mgn-replication.local"]))
            checks = [
                {
                    "key": "aws_identity",
                    "status": "passed",
                    "message": "Mock STS identity matches the configured target account.",
                    "account_id": expected_account_id,
                    "principal_arn": role_arn,
                },
                {
                    "key": "mgn_access",
                    "status": "passed",
                    "message": "Mock AWS MGN read access is available.",
                },
                {
                    "key": "source_to_staging_tcp_1500",
                    "status": "passed",
                    "message": "Mock TCP 1500 replication connectivity passed.",
                    "targets": hosts,
                },
            ]
            return {
                "action": normalized,
                "provider": "aws",
                "execution_mode": "mock",
                "mock": True,
                "region": region,
                "ready": True,
                "blocking_issue_count": 0,
                "checks": checks,
                "warning": "Simulation only: no AWS API or network call was made.",
            }

        servers = self._servers(source_refs, request)
        if normalized == "RECONCILE":
            return {
                "action": normalized,
                "provider": "aws",
                "execution_mode": "mock",
                "mock": True,
                "server_count": len(servers),
                "unresolved_source_refs": [],
                "servers": servers,
            }

        self._check_lifecycle(normalized, servers)
        target_lifecycle = {
            "START_TEST": "TESTING",
            "FINALIZE_TEST": "READY_FOR_CUTOVER",
            "START_CUTOVER": "CUTTING_OVER",
            "ROLLBACK": (
                "READY_FOR_CUTOVER"
                if request.get("rollback_to") == "ready-for-cutover"
                else "READY_FOR_TEST"
            ),
            "FINALIZE_CUTOVER": "CUTOVER",
        }[normalized]
        terminate = bool(request.get("terminate_instances", True))
        for server in servers:
            server["lifecycle_state"] = target_lifecycle
            if normalized in {"START_TEST", "START_CUTOVER"}:
                server["launched_ec2_instance_id"] = self._instance_id(server["source_ref"])
            elif normalized in {"FINALIZE_TEST", "ROLLBACK"} and terminate:
                server["launched_ec2_instance_id"] = None
            if normalized == "FINALIZE_CUTOVER":
                server["replication_state"] = "DISCONNECTED"
                server["is_archived"] = True
            server["workload_status"] = self._workload_status(
                server["lifecycle_state"], server["replication_state"]
            )

        return {
            "action": normalized,
            "provider": "aws",
            "execution_mode": "mock",
            "mock": True,
            "accepted": True,
            "job_id": job_id,
            "wave_id": wave_id,
            "mock_provider_job_id": "mock-" + hashlib.sha256(job_id.encode("utf-8")).hexdigest()[:16],
            "server_count": len(servers),
            "unresolved_source_refs": [],
            "servers": servers,
            "warning": "Simulation only: no AWS resource was created, changed, or deleted.",
        }
