#!/usr/bin/env python3
import argparse
import base64
import getpass
import json
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def encoded(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def secret(name: str, namespace: str, values: dict[str, str]) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace},
        "type": "Opaque",
        "data": {key: encoded(value) for key, value in values.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ignored development-only Kubernetes secrets and values.")
    parser.add_argument("--aws-account-id", required=True)
    parser.add_argument("--aws-region", default="us-east-1")
    parser.add_argument("--namespace", default="horizon-cloud-migration-dev")
    parser.add_argument("--installation-id", default="cloud-migration-dev-eks")
    parser.add_argument("--ldap-password", default="")
    args = parser.parse_args()
    if not (args.aws_account_id.isdigit() and len(args.aws_account_id) == 12):
        parser.error("--aws-account-id must be a 12-digit sandbox account ID")

    ldap_password = args.ldap_password or getpass.getpass("Shared development LDAP bind password: ")
    if not ldap_password:
        parser.error("LDAP bind password cannot be empty")

    repo_root = Path(__file__).resolve().parents[2]
    local_dir = repo_root / ".local"
    local_dir.mkdir(mode=0o700, exist_ok=True)
    postgres_password = secrets.token_urlsafe(24)
    session_secret = secrets.token_hex(32)
    signing_secret = secrets.token_hex(32)
    database_url = (
        f"postgresql+psycopg://cloud_migration:{postgres_password}"
        "@cloud-migration-postgresql:5432/cloud_migration"
    )

    license_doc = {
        "client_id": "horizon-cloud-migration-dev",
        "client_name": "Horizon Cloud Migration Development",
        "license_key": f"dev-{secrets.token_hex(12)}",
        "license_type": "development",
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=180)).isoformat().replace("+00:00", "Z"),
        "enabled_pipelines": ["Cloud Migration Factory"],
        "enabled_features": ["cloud_migration", "cloud_migration_aws"],
        "allowed_environments": ["DEV"],
        "allowed_aws_account_ids": [args.aws_account_id],
        "installation_id": args.installation_id,
        "license_mode": "offline-file",
        "signature_algorithm": "HMAC_SHA256",
        "signature_mode": "local-hmac",
        "signature_version": "1",
    }
    sys.path.insert(0, str(repo_root))
    from enterprise.licensing import sign_license

    license_doc["signature"] = sign_license(license_doc, signing_secret)

    items = [
        secret(
            "cloud-migration-runtime",
            args.namespace,
            {
                "postgres-password": postgres_password,
                "BACKEND_SESSION_SECRET": session_secret,
                "ENTERPRISE_LICENSE_SIGNING_SECRET": signing_secret,
            },
        ),
        secret("cloud-migration-database", args.namespace, {"DATABASE_URL": database_url}),
        secret("cloud-migration-license", args.namespace, {"license.json": json.dumps(license_doc, sort_keys=True)}),
        secret("cloud-migration-ldap-bind", args.namespace, {"password": ldap_password}),
    ]
    secret_path = local_dir / "cloud-migration-dev-secrets.json"
    secret_path.write_text(json.dumps({"apiVersion": "v1", "kind": "List", "items": items}, indent=2) + "\n")
    secret_path.chmod(0o600)

    role_arn = f"arn:aws:iam::{args.aws_account_id}:role/HorizonCloudMigrationSandboxRole"
    generated_values = {
        "enterprise": {"installationId": args.installation_id},
        "environmentCatalog": {
            "environments": [
                {
                    "name": "DEV",
                    "display_name": "Cloud Migration Sandbox",
                    "account_tier": "nonprod",
                    "aws_account_id": args.aws_account_id,
                    "aws_region": args.aws_region,
                    "client_aws_role_arn": role_arn,
                    "source_aws_role_arn": role_arn,
                    "target_aws_role_arn": role_arn,
                    "namespace_strategy": "auto",
                    "namespace_template": "{client_id}-{project_name}-{env}",
                    "iam_validation_mode": "validation-only",
                    "eks_access_mode": "namespace-scoped",
                    "is_active": True,
                }
            ]
        },
    }
    values_path = local_dir / "cloud-migration-dev-generated-values.json"
    values_path.write_text(json.dumps(generated_values, indent=2) + "\n")
    values_path.chmod(0o600)
    print(f"Generated {secret_path}")
    print(f"Generated {values_path}")
    print("These files are development-only, ignored by Git, and must not be used for production licensing.")


if __name__ == "__main__":
    main()
