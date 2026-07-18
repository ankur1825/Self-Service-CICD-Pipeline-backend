from ..contracts import AdapterCapability, ValidationAdapter


class StandardValidationAdapter(ValidationAdapter):
    def capabilities(self) -> AdapterCapability:
        return AdapterCapability(
            key="standard",
            kind="validation",
            display_name="Standard technical and application validation",
            adapter_version="v1alpha1",
            status="planning_only",
            target_providers=("aws",),
            strategies=("rehost", "replatform"),
            required_entitlements=("cloud_migration",),
            execution_mode="client-hosted",
            execution_enabled=False,
            license_mode="included",
            recommended=True,
            unavailable_reason="Live validation requires the client-hosted execution worker.",
        )
