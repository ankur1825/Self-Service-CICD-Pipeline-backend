import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from cloud_migration.providers.aws import AwsMigrationAdapter
from cloud_migration.adapters import adapter_registry
from cloud_migration.schemas import (
    MigrationProjectCreate,
    MigrationWaveApprovalRequest,
    MigrationWaveCreate,
    MigrationWorkloadCreate,
)
from cloud_migration.service import (
    approve_wave,
    capabilities,
    create_project,
    create_wave,
    migration_compatibility,
    plan_wave,
)
from database import Base
from models import EnvironmentCatalog


class AwsAdapterTest(unittest.TestCase):
    def test_registry_recommends_mgn_and_reports_optional_druva(self):
        with patch.dict(os.environ, {"CLOUD_MIGRATION_DRUVA_ENABLED": "false"}, clear=False):
            result = adapter_registry.compatibility("onprem-vmware", "aws")

        self.assertTrue(result["supported"])
        self.assertEqual(result["recommended_transfer_adapter"], "mgn")
        methods = {item["key"]: item for item in result["transfer_adapters"]}
        self.assertEqual(methods["mgn"]["status"], "available")
        self.assertEqual(methods["druva"]["status"], "not_configured")
        self.assertEqual(methods["druva"]["license_mode"], "bring-your-own-license")

    def test_registry_rejects_unregistered_target(self):
        result = adapter_registry.compatibility("aws-ec2", "azure")

        self.assertFalse(result["supported"])
        self.assertIn("not registered", result["reasons"][0])

    def test_plan_reports_blocking_catalog_gaps(self):
        adapter = AwsMigrationAdapter()
        project = SimpleNamespace(source_type="aws-ec2", target_environment="DEV", target_account_id="")
        wave = SimpleNamespace(source_region="", target_region="", migration_method="mgn")
        environment = SimpleNamespace(
            aws_account_id="",
            target_aws_role_arn="",
            client_aws_role_arn="",
        )

        plan = adapter.build_plan(project, wave, [], environment)

        self.assertGreaterEqual(plan["blocking_issue_count"], 4)
        self.assertEqual(plan["next_action"], "FIX_PLAN")

    def test_capabilities_explain_missing_license_entitlement(self):
        environment = {
            "CLOUD_MIGRATION_ENABLED": "true",
            "ENTERPRISE_LICENSE_ENFORCEMENT_ENABLED": "true",
            "ENTERPRISE_LICENSE_SIGNATURE_VERIFICATION_REQUIRED": "false",
            "ENTERPRISE_ENABLED_PIPELINES": "Build & Deploy Pipeline",
            "ENTERPRISE_ENABLED_FEATURES": "cloud_migration,cloud_migration_aws",
            "ENTERPRISE_LICENSE_EXPIRES_AT": "2099-12-31T23:59:59Z",
        }
        with patch.dict(os.environ, environment, clear=False):
            result = capabilities()

        self.assertFalse(result["licensed"])
        self.assertIn("not enabled", result["license_reason"])
        self.assertNotIn("license_key", result["license"])


class MigrationWorkflowTest(unittest.TestCase):
    def setUp(self):
        os.environ["CLOUD_MIGRATION_ENABLED"] = "true"
        os.environ["CLOUD_MIGRATION_AWS_ENABLED"] = "true"
        os.environ["CLOUD_MIGRATION_AWS_EXECUTION_ENABLED"] = "false"
        os.environ["ENTERPRISE_LICENSE_ENFORCEMENT_ENABLED"] = "false"
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = sessionmaker(bind=self.engine)()
        self.session.add(
            EnvironmentCatalog(
                name="DEV",
                display_name="Development",
                aws_account_id="123456789012",
                aws_region="us-east-1",
                client_aws_role_arn="arn:aws:iam::123456789012:role/migration-target",
                target_aws_role_arn="arn:aws:iam::123456789012:role/migration-target",
                is_active=1,
            )
        )
        self.session.commit()
        self.author = SimpleNamespace(
            username="architect",
            email="architect@client.example",
            roles=["migration-architect"],
        )
        self.approver = SimpleNamespace(
            username="approver",
            email="approver@client.example",
            roles=["migration-approver"],
        )

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_provider_neutral_schema_is_registered(self):
        inspector = inspect(self.engine)
        self.assertIn("cloud_migration_endpoints", inspector.get_table_names())
        self.assertIn("cloud_migration_transfer_profiles", inspector.get_table_names())
        project_columns = {column["name"] for column in inspector.get_columns("cloud_migration_projects")}
        wave_columns = {column["name"] for column in inspector.get_columns("cloud_migration_waves")}
        self.assertTrue({"source_endpoint_id", "target_endpoint_id"}.issubset(project_columns))
        self.assertTrue({"migration_strategy", "transfer_profile_id"}.issubset(wave_columns))

    def test_project_wave_plan_and_separate_approval(self):
        project = create_project(
            self.session,
            self.author,
            MigrationProjectCreate(
                name="Payments rehost",
                source_type="aws-ec2",
                target_environment="DEV",
            ),
        )
        wave = create_wave(
            self.session,
            self.author,
            project["id"],
            MigrationWaveCreate(
                name="Wave 1",
                migration_method="mgn",
                source_region="us-west-2",
                workloads=[MigrationWorkloadCreate(source_ref="i-0123456789abcdef0")],
            ),
        )

        planned = plan_wave(self.session, self.author, wave["id"], expected_version=0)
        self.assertEqual(planned["status"], "PLANNED")
        self.assertEqual(planned["plan_version"], 1)
        self.assertFalse(planned["plan"]["execution_enabled"])

        with self.assertRaises(HTTPException) as self_approval:
            approve_wave(
                self.session,
                SimpleNamespace(
                    username="architect",
                    email="architect@client.example",
                    roles=["platform-admin"],
                ),
                wave["id"],
                MigrationWaveApprovalRequest(expected_version=1),
            )
        self.assertEqual(self_approval.exception.status_code, 409)

        approved = approve_wave(
            self.session,
            self.approver,
            wave["id"],
            MigrationWaveApprovalRequest(expected_version=1, comment="CAB-1042"),
        )
        self.assertEqual(approved["status"], "APPROVED")
        self.assertEqual(approved["approved_by"], "approver@client.example")

    def test_incompatible_transfer_method_is_rejected(self):
        project = create_project(
            self.session,
            self.author,
            MigrationProjectCreate(
                name="On-premises rehost",
                source_type="onprem-physical",
                target_environment="DEV",
            ),
        )

        with self.assertRaises(HTTPException) as rejected:
            create_wave(
                self.session,
                self.author,
                project["id"],
                MigrationWaveCreate(
                    name="Wave 1",
                    migration_method="ami-copy",
                    workloads=[MigrationWorkloadCreate(source_ref="server-001")],
                ),
            )

        self.assertEqual(rejected.exception.status_code, 422)

    def test_compatibility_api_service_enforces_role(self):
        result = migration_compatibility(self.author, "aws-ec2", "aws")
        self.assertTrue(result["supported"])

        with self.assertRaises(HTTPException) as forbidden:
            migration_compatibility(SimpleNamespace(roles=["developer"]), "aws-ec2", "aws")
        self.assertEqual(forbidden.exception.status_code, 403)

    def test_optional_druva_adapter_requires_product_entitlement(self):
        license_environment = {
            "CLOUD_MIGRATION_DRUVA_ENABLED": "true",
            "ENTERPRISE_LICENSE_ENFORCEMENT_ENABLED": "true",
            "ENTERPRISE_LICENSE_SIGNATURE_VERIFICATION_REQUIRED": "false",
            "ENTERPRISE_CLIENT_ID": "client-a",
            "ENTERPRISE_LICENSE_KEY": "test-license",
            "ENTERPRISE_LICENSE_EXPIRES_AT": "2099-12-31T23:59:59Z",
            "ENTERPRISE_ENABLED_PIPELINES": "Cloud Migration Factory",
            "ENTERPRISE_ENABLED_FEATURES": "cloud_migration,cloud_migration_aws",
            "ENTERPRISE_ALLOWED_ENVIRONMENTS": "DEV",
        }
        with patch.dict(os.environ, license_environment, clear=False):
            result = migration_compatibility(self.author, "onprem-vmware", "aws")

        methods = {item["key"]: item for item in result["transfer_adapters"]}
        self.assertEqual(methods["mgn"]["status"], "available")
        self.assertEqual(methods["druva"]["status"], "unlicensed")
        self.assertIn("cloud_migration_druva", methods["druva"]["unavailable_reason"])


if __name__ == "__main__":
    unittest.main()
