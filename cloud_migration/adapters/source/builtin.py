from ..contracts import AdapterCapability, SourceConnector


class BuiltinSourceConnector(SourceConnector):
    def __init__(self, *, key: str, display_name: str) -> None:
        self.key = key
        self.display_name = display_name

    def capabilities(self) -> AdapterCapability:
        return AdapterCapability(
            key=self.key,
            kind="source",
            display_name=self.display_name,
            adapter_version="v1alpha1",
            status="available",
            source_types=(self.key,),
            execution_mode="client-hosted",
            execution_enabled=False,
            required_entitlements=("cloud_migration",),
        )
