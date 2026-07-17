import os
import re
from typing import Any, Dict, Iterable, List

from .base import MigrationProviderAdapter


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class AwsMigrationAdapter(MigrationProviderAdapter):
    provider = "aws"
    adapter_version = "v1alpha1"

    def capabilities(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "display_name": "Amazon Web Services",
            "status": "available" if _env_bool("CLOUD_MIGRATION_AWS_ENABLED", True) else "disabled",
            "adapter_version": self.adapter_version,
            "source_types": ["aws-ec2", "external"],
            "migration_methods": [
                {
                    "key": "mgn",
                    "display_name": "AWS MGN continuous replication",
                    "recommended": True,
                },
                {
                    "key": "ami-copy",
                    "display_name": "AMI / snapshot copy",
                    "recommended": False,
                },
            ],
            "lifecycle": [
                "DRAFT",
                "PLANNED",
                "APPROVED",
                "REPLICATING",
                "TEST_READY",
                "TESTED",
                "CUTOVER_READY",
                "CUTOVER_COMPLETE",
                "FINALIZED",
            ],
            "execution_enabled": _env_bool("CLOUD_MIGRATION_AWS_EXECUTION_ENABLED", False),
            "data_boundary": os.getenv("CLOUD_MIGRATION_DATA_BOUNDARY", "client-hosted"),
            "required_entitlements": ["cloud_migration", "cloud_migration_aws"],
        }

    def build_plan(self, project: Any, wave: Any, workloads: Iterable[Any], environment: Any) -> Dict[str, Any]:
        workload_list = list(workloads)
        checks: List[Dict[str, str]] = []

        def check(key: str, ok: bool, message: str, severity: str = "error") -> None:
            checks.append({
                "key": key,
                "status": "passed" if ok else "failed",
                "severity": "info" if ok else severity,
                "message": message,
            })

        check("provider_enabled", _env_bool("CLOUD_MIGRATION_AWS_ENABLED", True), "AWS migration adapter is enabled.")
        check("workloads_present", bool(workload_list), "At least one workload is required.")
        account_id = str(getattr(environment, "aws_account_id", "") or "")
        check("target_account", bool(re.fullmatch(r"\d{12}", account_id)), "Target AWS account is a 12-digit account ID in Environment Catalog.")
        region_pattern = r"^[a-z]{2}(?:-[a-z0-9]+)+-\d$"
        check("target_region", bool(re.fullmatch(region_pattern, str(wave.target_region or ""))), "Target AWS Region is configured and valid.")
        target_role = getattr(environment, "target_aws_role_arn", "") or getattr(environment, "client_aws_role_arn", "")
        check(
            "target_role",
            bool(re.fullmatch(r"arn:[^:]+:iam::\d{12}:role/.+", str(target_role or ""))),
            "Target AWS IAM role ARN is configured in Environment Catalog.",
        )

        if project.source_type == "aws-ec2":
            check("source_region", bool(re.fullmatch(region_pattern, str(wave.source_region or ""))), "Source AWS Region is configured and valid.")

        if wave.migration_method == "mgn":
            check(
                "mgn_credentials",
                True,
                "Use AWSApplicationMigrationServiceEc2InstancePolicy for EC2 sources or short-lived installation credentials for external sources.",
            )
            check(
                "mgn_network",
                True,
                "Preflight must verify TCP 443 to target-region MGN endpoints and TCP 1500 to the staging subnet before execution.",
            )

        blocking = [item for item in checks if item["status"] == "failed" and item["severity"] == "error"]
        return {
            "provider": self.provider,
            "adapter_version": self.adapter_version,
            "data_boundary": os.getenv("CLOUD_MIGRATION_DATA_BOUNDARY", "client-hosted"),
            "execution_enabled": _env_bool("CLOUD_MIGRATION_AWS_EXECUTION_ENABLED", False),
            "migration_method": wave.migration_method,
            "source": {
                "type": project.source_type,
                "region": wave.source_region,
            },
            "target": {
                "environment": project.target_environment,
                "account_id": project.target_account_id,
                "region": wave.target_region,
                "role_arn": target_role,
            },
            "workload_count": len(workload_list),
            "workloads": [
                {
                    "source_ref": workload.source_ref,
                    "hostname": workload.hostname,
                    "os_family": workload.os_family,
                    "target_instance_type": workload.target_instance_type,
                }
                for workload in workload_list
            ],
            "checks": checks,
            "blocking_issue_count": len(blocking),
            "next_action": "APPROVAL" if not blocking else "FIX_PLAN",
        }
