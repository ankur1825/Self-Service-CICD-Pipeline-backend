import ipaddress
import json
import os
import re
import socket
import ssl
import time
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Sequence

import boto3
from botocore.config import Config


MGN_SOURCE_ID = re.compile(r"^s-[0-9A-Za-z]{17}$")
READ_ACTIONS = {"PREFLIGHT", "RECONCILE"}
MUTATING_ACTIONS = {
    "START_TEST",
    "FINALIZE_TEST",
    "START_CUTOVER",
    "ROLLBACK",
    "FINALIZE_CUTOVER",
}


class AwsExecutionError(RuntimeError):
    pass


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def _json_safe(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _session_policy(action: str) -> str:
    actions = ["mgn:DescribeSourceServers", "mgn:DescribeJobs"]
    action_permissions = {
        "START_TEST": ["mgn:StartTest"],
        "FINALIZE_TEST": ["mgn:ChangeServerLifeCycleState", "mgn:TerminateTargetInstances"],
        "START_CUTOVER": ["mgn:StartCutover"],
        "ROLLBACK": ["mgn:ChangeServerLifeCycleState", "mgn:TerminateTargetInstances"],
        "FINALIZE_CUTOVER": ["mgn:FinalizeCutover"],
    }
    actions.extend(action_permissions.get(action, []))
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": sorted(set(actions)), "Resource": "*"}],
    }
    return json.dumps(document, separators=(",", ":"), sort_keys=True)


def _session_name(job_id: str) -> str:
    suffix = re.sub(r"[^A-Za-z0-9+=,.@-]", "-", job_id)[:40]
    return f"horizon-migration-{suffix}"[:64]


def _safe_probe_host(value: str) -> str:
    host = str(value or "").strip().rstrip(".")
    if not host or len(host) > 253 or "/" in host or "://" in host:
        raise AwsExecutionError(f"Invalid TCP probe host '{host[:80]}'.")
    try:
        address = ipaddress.ip_address(host)
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise AwsExecutionError(f"TCP probe host '{host}' is not an allowed network target.")
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
            raise AwsExecutionError(f"Invalid TCP probe host '{host[:80]}'.")
    return host


def _resolved_addresses(host: str, port: int) -> List[str]:
    values: List[str] = []
    for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        address = item[4][0]
        parsed = ipaddress.ip_address(address)
        if parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified:
            raise AwsExecutionError(f"Probe target '{host}' resolved to a disallowed address.")
        if address not in values:
            values.append(address)
    if not values:
        raise AwsExecutionError(f"Probe target '{host}' did not resolve.")
    return values[:5]


def _tcp_probe(host: str, port: int, timeout_seconds: float, tls: bool = False) -> Dict[str, Any]:
    host = _safe_probe_host(host)
    started = time.monotonic()
    addresses = _resolved_addresses(host, port)
    with socket.create_connection((host, port), timeout=timeout_seconds) as connection:
        if tls:
            context = ssl.create_default_context()
            with context.wrap_socket(connection, server_hostname=host) as secured:
                secured.do_handshake()
    return {
        "host": host,
        "port": port,
        "status": "passed",
        "tls": tls,
        "resolved_addresses": addresses,
        "latency_ms": round((time.monotonic() - started) * 1000, 1),
    }


def _check(key: str, passed: bool, message: str, **details: Any) -> Dict[str, Any]:
    return {
        "key": key,
        "status": "passed" if passed else "failed",
        "message": message,
        **_json_safe(details),
    }


class AwsExecutionAdapter:
    """AWS execution implementation that never persists temporary AWS credentials."""

    def __init__(self) -> None:
        self.config = Config(
            connect_timeout=_env_int("CLOUD_MIGRATION_AWS_CONNECT_TIMEOUT_SECONDS", 5, 1, 30),
            read_timeout=_env_int("CLOUD_MIGRATION_AWS_READ_TIMEOUT_SECONDS", 30, 5, 120),
            retries={"mode": "standard", "max_attempts": 3},
        )

    def session(self, *, region: str, role_arn: str, action: str, job_id: str) -> boto3.Session:
        base = boto3.Session(region_name=region)
        if not role_arn:
            return base
        request: Dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": _session_name(job_id),
            "DurationSeconds": _env_int("CLOUD_MIGRATION_AWS_SESSION_SECONDS", 900, 900, 3600),
            "Policy": _session_policy(action),
        }
        external_id = os.getenv("CLOUD_MIGRATION_AWS_EXTERNAL_ID", "").strip()
        if external_id:
            request["ExternalId"] = external_id
        response = base.client("sts", region_name=region, config=self.config).assume_role(**request)
        credentials = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region,
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
            raise AwsExecutionError(f"Unsupported AWS execution action '{normalized}'.")
        session = self.session(
            region=region,
            role_arn=role_arn,
            action=normalized,
            job_id=job_id,
        )
        if normalized == "PREFLIGHT":
            return self.preflight(
                session=session,
                region=region,
                expected_account_id=expected_account_id,
                tcp1500_hosts=request.get("tcp1500_hosts") or [],
            )

        mgn = session.client("mgn", region_name=region, config=self.config)
        observed = self.describe_sources(mgn, source_refs)
        if normalized == "RECONCILE":
            return observed
        return self.mutate(
            mgn=mgn,
            action=normalized,
            job_id=job_id,
            wave_id=wave_id,
            source_refs=source_refs,
            request=request,
            observed=observed,
        )

    def preflight(
        self,
        *,
        session: boto3.Session,
        region: str,
        expected_account_id: str,
        tcp1500_hosts: Sequence[str],
    ) -> Dict[str, Any]:
        checks: List[Dict[str, Any]] = []
        timeout = float(_env_int("CLOUD_MIGRATION_NETWORK_PROBE_TIMEOUT_SECONDS", 5, 1, 30))
        for key, host in (
            ("sts_tcp_443", f"sts.{region}.amazonaws.com"),
            ("mgn_tcp_443", f"mgn.{region}.amazonaws.com"),
        ):
            try:
                details = _tcp_probe(host, 443, timeout, tls=True)
                checks.append(_check(key, True, f"TLS connectivity to {host}:443 succeeded.", details=details))
            except Exception as exc:
                checks.append(_check(key, False, f"TLS connectivity to {host}:443 failed.", error=str(exc)[:500]))

        try:
            identity = session.client("sts", region_name=region, config=self.config).get_caller_identity()
            actual_account = str(identity.get("Account") or "")
            checks.append(
                _check(
                    "aws_identity",
                    actual_account == expected_account_id,
                    "AWS caller identity matches the wave target account."
                    if actual_account == expected_account_id
                    else "AWS caller identity does not match the wave target account.",
                    account_id=actual_account,
                    principal_arn=identity.get("Arn"),
                )
            )
        except Exception as exc:
            checks.append(_check("aws_identity", False, "AWS STS identity validation failed.", error=str(exc)[:500]))

        try:
            session.client("mgn", region_name=region, config=self.config).describe_source_servers(maxResults=1)
            checks.append(_check("mgn_access", True, "AWS MGN read access is available in the target Region."))
        except Exception as exc:
            checks.append(_check("mgn_access", False, "AWS MGN read access or initialization check failed.", error=str(exc)[:500]))

        unique_hosts = list(dict.fromkeys(_safe_probe_host(item) for item in tcp1500_hosts))
        if not unique_hosts:
            checks.append(
                _check(
                    "source_to_staging_tcp_1500",
                    False,
                    "No MGN replication-server targets were supplied for the source-network TCP 1500 probe.",
                    vantage=os.getenv("CLOUD_MIGRATION_NETWORK_VANTAGE", "client-worker"),
                )
            )
        else:
            failures = []
            results = []
            for host in unique_hosts:
                try:
                    results.append(_tcp_probe(host, 1500, timeout, tls=False))
                except Exception as exc:
                    failures.append({"host": host, "error": str(exc)[:500]})
            checks.append(
                _check(
                    "source_to_staging_tcp_1500",
                    not failures,
                    "TCP 1500 connectivity to every supplied MGN replication target succeeded."
                    if not failures
                    else "TCP 1500 connectivity failed for one or more supplied MGN replication targets.",
                    vantage=os.getenv("CLOUD_MIGRATION_NETWORK_VANTAGE", "client-worker"),
                    results=results,
                    failures=failures,
                )
            )

        failed = [item for item in checks if item["status"] == "failed"]
        return {
            "action": "PREFLIGHT",
            "provider": "aws",
            "region": region,
            "ready": not failed,
            "blocking_issue_count": len(failed),
            "checks": checks,
        }

    def describe_sources(self, mgn: Any, source_refs: Sequence[str]) -> Dict[str, Any]:
        refs = [str(item).strip() for item in source_refs if str(item).strip()]
        if not refs:
            raise AwsExecutionError("The wave has no workload source references.")
        items: List[Dict[str, Any]] = []
        request: Dict[str, Any] = {"maxResults": 1000}
        if all(MGN_SOURCE_ID.fullmatch(item) for item in refs):
            request["filters"] = {"sourceServerIDs": refs}
        while True:
            response = mgn.describe_source_servers(**request)
            items.extend(response.get("items") or [])
            token = response.get("nextToken")
            if not token:
                break
            request["nextToken"] = token

        candidates: Dict[str, Dict[str, Any]] = {}
        for item in items:
            hints = (item.get("sourceProperties") or {}).get("identificationHints") or {}
            for key in (
                item.get("sourceServerID"),
                item.get("userProvidedID"),
                hints.get("hostname"),
                hints.get("fqdn"),
            ):
                if key:
                    candidates[str(key).strip().lower()] = item

        servers = []
        unresolved = []
        for ref in refs:
            item = candidates.get(ref.lower())
            if not item:
                unresolved.append(ref)
                continue
            lifecycle = (item.get("lifeCycle") or {}).get("state") or "UNKNOWN"
            replication = item.get("dataReplicationInfo") or {}
            launched = item.get("launchedInstance") or {}
            servers.append(
                {
                    "source_ref": ref,
                    "source_server_id": item.get("sourceServerID"),
                    "user_provided_id": item.get("userProvidedID"),
                    "lifecycle_state": lifecycle,
                    "replication_state": replication.get("dataReplicationState") or "UNKNOWN",
                    "lag_duration": replication.get("lagDuration"),
                    "last_snapshot_date_time": replication.get("lastSnapshotDateTime"),
                    "launched_ec2_instance_id": launched.get("ec2InstanceID"),
                    "is_archived": bool(item.get("isArchived")),
                    "workload_status": self.workload_status(lifecycle, replication.get("dataReplicationState")),
                }
            )
        return {
            "action": "RECONCILE",
            "provider": "aws",
            "server_count": len(servers),
            "unresolved_source_refs": unresolved,
            "servers": _json_safe(servers),
        }

    @staticmethod
    def workload_status(lifecycle: str, replication: str | None) -> str:
        return {
            "STOPPED": "REPLICATION_STOPPED",
            "NOT_READY": "REPLICATING" if replication not in {"STALLED", "STOPPED"} else "REPLICATION_BLOCKED",
            "READY_FOR_TEST": "TEST_READY",
            "TESTING": "TEST_IN_PROGRESS",
            "READY_FOR_CUTOVER": "CUTOVER_READY",
            "CUTTING_OVER": "CUTOVER_IN_PROGRESS",
            "CUTOVER": "CUTOVER_COMPLETE",
            "DISCONNECTED": "DISCONNECTED",
            "DISCOVERED": "DISCOVERED",
            "PENDING_INSTALLATION": "AGENT_PENDING",
        }.get(lifecycle, "UNKNOWN")

    def mutate(
        self,
        *,
        mgn: Any,
        action: str,
        job_id: str,
        wave_id: str,
        source_refs: Sequence[str],
        request: Dict[str, Any],
        observed: Dict[str, Any],
    ) -> Dict[str, Any]:
        unresolved = observed.get("unresolved_source_refs") or []
        if unresolved:
            raise AwsExecutionError(f"MGN source servers were not resolved for: {', '.join(unresolved)}")
        servers = observed.get("servers") or []
        source_ids = [item["source_server_id"] for item in servers]
        states = {item["lifecycle_state"] for item in servers}
        tags = {"HorizonWave": wave_id[:256], "HorizonJob": job_id[:256]}

        if action == "START_TEST":
            if states == {"TESTING"}:
                return self._mutation_result(action, observed, already_applied=True)
            self._require_states(action, states, {"READY_FOR_TEST"})
            response = mgn.start_test(sourceServerIDs=source_ids, tags=tags)
            return self._mutation_result(action, observed, aws_job=self._job_summary(response.get("job")))

        if action == "FINALIZE_TEST":
            self._require_states(action, states, {"TESTING", "READY_FOR_CUTOVER"})
            changed = []
            for item in servers:
                if item["lifecycle_state"] != "READY_FOR_CUTOVER":
                    mgn.change_server_life_cycle_state(
                        sourceServerID=item["source_server_id"],
                        lifeCycle={"state": "READY_FOR_CUTOVER"},
                    )
                    changed.append(item["source_server_id"])
            termination = None
            if request.get("terminate_instances", True):
                termination = self._job_summary(
                    (mgn.terminate_target_instances(sourceServerIDs=source_ids, tags=tags) or {}).get("job")
                )
            return self._mutation_result(action, observed, changed_source_server_ids=changed, aws_job=termination)

        if action == "START_CUTOVER":
            if states == {"CUTTING_OVER"}:
                return self._mutation_result(action, observed, already_applied=True)
            self._require_states(action, states, {"READY_FOR_CUTOVER"})
            response = mgn.start_cutover(sourceServerIDs=source_ids, tags=tags)
            return self._mutation_result(action, observed, aws_job=self._job_summary(response.get("job")))

        if action == "ROLLBACK":
            target = request.get("rollback_to") or "ready-for-test"
            target_state = "READY_FOR_CUTOVER" if target == "ready-for-cutover" else "READY_FOR_TEST"
            allowed = {target_state, "CUTTING_OVER"} if target_state == "READY_FOR_CUTOVER" else {target_state, "TESTING", "READY_FOR_CUTOVER"}
            self._require_states(action, states, allowed)
            changed = []
            for item in servers:
                if item["lifecycle_state"] != target_state:
                    mgn.change_server_life_cycle_state(
                        sourceServerID=item["source_server_id"],
                        lifeCycle={"state": target_state},
                    )
                    changed.append(item["source_server_id"])
            termination = None
            if request.get("terminate_instances", True):
                termination = self._job_summary(
                    (mgn.terminate_target_instances(sourceServerIDs=source_ids, tags=tags) or {}).get("job")
                )
            return self._mutation_result(
                action,
                observed,
                rollback_state=target_state,
                changed_source_server_ids=changed,
                aws_job=termination,
            )

        if action == "FINALIZE_CUTOVER":
            self._require_states(action, states, {"CUTTING_OVER", "CUTOVER"})
            finalized = []
            for item in servers:
                if item["lifecycle_state"] != "CUTOVER":
                    mgn.finalize_cutover(sourceServerID=item["source_server_id"])
                    finalized.append(item["source_server_id"])
            return self._mutation_result(action, observed, finalized_source_server_ids=finalized)

        raise AwsExecutionError(f"Unsupported AWS mutation action '{action}'.")

    @staticmethod
    def _require_states(action: str, actual: set[str], allowed: set[str]) -> None:
        if not actual.issubset(allowed):
            raise AwsExecutionError(
                f"Action {action} requires lifecycle states {sorted(allowed)}; observed {sorted(actual)}."
            )

    @staticmethod
    def _job_summary(job: Any) -> Dict[str, Any] | None:
        if not job:
            return None
        return _json_safe(
            {
                "job_id": job.get("jobID"),
                "type": job.get("type"),
                "status": job.get("status"),
                "creation_date_time": job.get("creationDateTime"),
                "participating_servers": [
                    {
                        "source_server_id": item.get("sourceServerID"),
                        "launched_ec2_instance_id": item.get("launchedEc2InstanceID"),
                    }
                    for item in (job.get("participatingServers") or [])
                ],
            }
        )

    @staticmethod
    def _mutation_result(action: str, observed: Dict[str, Any], **details: Any) -> Dict[str, Any]:
        return {
            "action": action,
            "provider": "aws",
            "accepted": True,
            "observed_before_action": observed,
            **_json_safe(details),
        }
