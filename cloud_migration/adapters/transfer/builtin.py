import os

from ..contracts import AdapterCapability, TransferAdapter


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


AWS_MGN_SOURCES = (
    "external",
    "onprem-vmware",
    "onprem-physical",
    "aws-ec2",
    "azure-vm",
    "gcp-vm",
    "oci-compute",
)


class AwsMgnTransferAdapter(TransferAdapter):
    def capabilities(self) -> AdapterCapability:
        provider_enabled = _env_bool("CLOUD_MIGRATION_AWS_ENABLED", True)
        return AdapterCapability(
            key="mgn",
            kind="transfer",
            display_name="AWS Application Migration Service (MGN)",
            adapter_version="v1alpha1",
            status="available" if provider_enabled else "disabled",
            source_types=AWS_MGN_SOURCES,
            target_providers=("aws",),
            strategies=("rehost",),
            required_entitlements=("cloud_migration", "cloud_migration_aws"),
            execution_mode="client-hosted",
            execution_enabled=provider_enabled and _env_bool("CLOUD_MIGRATION_AWS_EXECUTION_ENABLED", False),
            license_mode="cloud-native-consumption",
            recommended=True,
            unavailable_reason=None if provider_enabled else "The AWS provider is disabled for this installation.",
        )


class AwsAmiCopyTransferAdapter(TransferAdapter):
    def capabilities(self) -> AdapterCapability:
        provider_enabled = _env_bool("CLOUD_MIGRATION_AWS_ENABLED", True)
        return AdapterCapability(
            key="ami-copy",
            kind="transfer",
            display_name="AWS AMI / encrypted snapshot copy",
            adapter_version="v1alpha1",
            status="available" if provider_enabled else "disabled",
            source_types=("aws-ec2",),
            target_providers=("aws",),
            strategies=("rehost",),
            required_entitlements=("cloud_migration", "cloud_migration_aws"),
            execution_mode="client-hosted",
            execution_enabled=provider_enabled and _env_bool("CLOUD_MIGRATION_AWS_EXECUTION_ENABLED", False),
            license_mode="cloud-native-consumption",
            unavailable_reason=None if provider_enabled else "The AWS provider is disabled for this installation.",
        )


class DruvaTransferAdapter(TransferAdapter):
    def capabilities(self) -> AdapterCapability:
        configured = _env_bool("CLOUD_MIGRATION_DRUVA_ENABLED", False)
        return AdapterCapability(
            key="druva",
            kind="transfer",
            display_name="Druva backup and restore",
            adapter_version="v1alpha1",
            status="available" if configured else "not_configured",
            source_types=("onprem-vmware",),
            target_providers=("aws",),
            strategies=("rehost", "backup-restore"),
            required_entitlements=("cloud_migration", "cloud_migration_druva"),
            execution_mode="client-hosted",
            execution_enabled=False,
            license_mode="bring-your-own-license",
            unavailable_reason=None if configured else "Druva requires a client-owned enterprise license and connector configuration.",
        )
