from ..contracts import AdapterCapability, InfrastructureProvisioner


class TerraformProvisioner(InfrastructureProvisioner):
    def capabilities(self) -> AdapterCapability:
        return AdapterCapability(
            key="terraform",
            kind="provisioner",
            display_name="Terraform landing-zone provisioner",
            adapter_version="v1alpha1",
            status="planning_only",
            target_providers=("aws",),
            strategies=("rehost", "replatform"),
            required_entitlements=("cloud_migration", "cloud_migration_aws"),
            execution_mode="client-hosted",
            execution_enabled=False,
            license_mode="open-source",
            recommended=True,
            unavailable_reason="Apply is locked until the client-hosted worker and approval gates are enabled.",
        )
