import os

from ..contracts import AdapterCapability, TargetProviderAdapter


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class AwsTargetAdapter(TargetProviderAdapter):
    def capabilities(self) -> AdapterCapability:
        enabled = _env_bool("CLOUD_MIGRATION_AWS_ENABLED", True)
        return AdapterCapability(
            key="aws",
            kind="target",
            display_name="Amazon Web Services",
            adapter_version="v1alpha1",
            status="available" if enabled else "disabled",
            target_providers=("aws",),
            strategies=("rehost", "replatform"),
            required_entitlements=("cloud_migration", "cloud_migration_aws"),
            execution_mode="client-hosted",
            execution_enabled=enabled and _env_bool("CLOUD_MIGRATION_AWS_EXECUTION_ENABLED", False),
            license_mode="included",
            unavailable_reason=None if enabled else "The AWS provider is disabled for this installation.",
        )
