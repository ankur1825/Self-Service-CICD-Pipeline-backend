#!/usr/bin/env python3
import argparse
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare ignored local Cloud Migration test secrets and configuration.")
    parser.add_argument("--aws-account-id", default="111122223333")
    parser.add_argument("--aws-region", default="us-east-1")
    parser.add_argument("--port", default="8080")
    args = parser.parse_args()

    if not (args.aws_account_id.isdigit() and len(args.aws_account_id) == 12):
        parser.error("--aws-account-id must be a 12-digit sandbox account ID")

    repo_root = Path(__file__).resolve().parents[2]
    local_dir = repo_root / ".local"
    local_dir.mkdir(mode=0o700, exist_ok=True)

    ui_candidates = [
        repo_root.parent / "ui",
        repo_root.parent / "Self-Service-CICD-Pipeline-UI",
    ]
    ui_context = next((path for path in ui_candidates if (path / "package.json").exists()), None)
    if not ui_context:
        parser.error("Unable to locate the UI repository. Expected ../ui or ../Self-Service-CICD-Pipeline-UI")

    db_password = secrets.token_urlsafe(24)
    ldap_admin_password = secrets.token_urlsafe(24)
    session_secret = secrets.token_hex(32)
    license_secret = secrets.token_hex(32)
    installation_id = f"local-cloud-migration-{secrets.token_hex(8)}"

    runtime_values = {
        "UI_CONTEXT": str(ui_context),
        "CLOUD_MIGRATION_PORT": args.port,
        "POSTGRES_PASSWORD": db_password,
        "DATABASE_URL": f"postgresql+psycopg://cloud_migration:{db_password}@postgres:5432/cloud_migration",
        "LDAP_ADMIN_PASSWORD": ldap_admin_password,
        "LDAP_MANAGER_PASSWORD": ldap_admin_password,
        "BACKEND_SESSION_SECRET": session_secret,
        "ENTERPRISE_LICENSE_SIGNING_SECRET": license_secret,
    }
    runtime_path = local_dir / "runtime.env"
    runtime_path.write_text("".join(f"{key}={value}\n" for key, value in runtime_values.items()))
    runtime_path.chmod(0o600)

    license_doc = {
        "client_id": "local-enterprise-client",
        "client_name": "Local Enterprise Client",
        "license_key": f"local-{secrets.token_hex(12)}",
        "license_type": "development",
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat().replace("+00:00", "Z"),
        "enabled_pipelines": ["Cloud Migration Factory"],
        "enabled_features": ["cloud_migration", "cloud_migration_aws"],
        "allowed_environments": ["DEV"],
        "allowed_aws_account_ids": [args.aws_account_id],
        "installation_id": installation_id,
        "license_mode": "offline-file",
        "signature_algorithm": "HMAC_SHA256",
        "signature_mode": "local-hmac",
        "signature_version": "1",
    }
    import sys

    sys.path.insert(0, str(repo_root))
    from enterprise.licensing import sign_license

    license_doc["signature"] = sign_license(license_doc, license_secret)
    license_path = local_dir / "license.json"
    license_path.write_text(json.dumps(license_doc, indent=2, sort_keys=True) + "\n")
    license_path.chmod(0o600)

    role_arn = f"arn:aws:iam::{args.aws_account_id}:role/HorizonCloudMigrationSandboxRole"
    catalog = {
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
    }
    catalog_path = local_dir / "environment-catalog.json"
    catalog_path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")
    catalog_path.chmod(0o600)

    print(f"Prepared local runtime in {local_dir}")
    print(f"UI: http://127.0.0.1:{args.port}/pipeline/")
    print("Test users: migration-admin, migration-architect, migration-operator, migration-approver, migration-auditor")
    print("Local-only test password: MigrationTest!2026")


if __name__ == "__main__":
    main()
