from collections import defaultdict
from typing import Any, Dict, Iterable, List

from .contracts import AdapterCapability, MigrationAdapter
from .provisioner import TerraformProvisioner
from .source import BuiltinSourceConnector
from .target import AwsTargetAdapter
from .transfer import AwsAmiCopyTransferAdapter, AwsMgnTransferAdapter, DruvaTransferAdapter
from .validation import StandardValidationAdapter


class AdapterRegistry:
    def __init__(self, adapters: Iterable[MigrationAdapter] = ()) -> None:
        self._adapters: Dict[tuple[str, str], MigrationAdapter] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: MigrationAdapter) -> None:
        capability = adapter.capabilities()
        identity = (capability.kind, capability.key)
        if identity in self._adapters:
            raise ValueError(f"Adapter '{capability.kind}/{capability.key}' is already registered.")
        self._adapters[identity] = adapter

    def capabilities(self, kind: str | None = None) -> List[AdapterCapability]:
        capabilities = [adapter.capabilities() for adapter in self._adapters.values()]
        if kind:
            capabilities = [item for item in capabilities if item.kind == kind]
        return sorted(capabilities, key=lambda item: (item.kind, item.display_name.lower()))

    def get(self, kind: str, key: str) -> MigrationAdapter | None:
        return self._adapters.get((kind, key))

    def catalog(self) -> Dict[str, Any]:
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for capability in self.capabilities():
            grouped[f"{capability.kind}_adapters"].append(capability.to_dict())
        return {
            "contract_version": "v1alpha1",
            "data_boundary": "client-hosted",
            "execution_default": "locked",
            **dict(grouped),
        }

    def compatibility(self, source_type: str, target_provider: str, strategy: str = "rehost") -> Dict[str, Any]:
        source = self.get("source", source_type)
        target = self.get("target", target_provider)
        source_capability = source.capabilities() if source else None
        target_capability = target.capabilities() if target else None
        transfer_capabilities = [
            capability
            for capability in self.capabilities("transfer")
            if capability.supports(source_type, target_provider, strategy)
        ]
        available = [item for item in transfer_capabilities if item.status == "available"]
        recommended = next((item.key for item in available if item.recommended), None)
        if not recommended and available:
            recommended = available[0].key

        reasons: List[str] = []
        if not source_capability:
            reasons.append(f"Source type '{source_type}' is not registered.")
        if not target_capability:
            reasons.append(f"Target provider '{target_provider}' is not registered.")
        elif target_capability.status != "available":
            reasons.append(target_capability.unavailable_reason or f"Target provider '{target_provider}' is unavailable.")
        if source_capability and target_capability and not available:
            reasons.append("No available transfer adapter supports this source, target, and strategy combination.")

        return {
            "source_type": source_type,
            "target_provider": target_provider,
            "strategy": strategy,
            "supported": bool(source_capability and target_capability and target_capability.status == "available" and available),
            "recommended_transfer_adapter": recommended,
            "source_adapter": source_capability.to_dict() if source_capability else None,
            "target_adapter": target_capability.to_dict() if target_capability else None,
            "transfer_adapters": [item.to_dict() for item in transfer_capabilities],
            "reasons": reasons,
        }


adapter_registry = AdapterRegistry(
    [
        BuiltinSourceConnector(key="external", display_name="External / legacy source"),
        BuiltinSourceConnector(key="onprem-vmware", display_name="On-premises VMware virtual machine"),
        BuiltinSourceConnector(key="onprem-physical", display_name="On-premises physical server"),
        BuiltinSourceConnector(key="aws-ec2", display_name="AWS EC2 instance"),
        BuiltinSourceConnector(key="azure-vm", display_name="Microsoft Azure virtual machine"),
        BuiltinSourceConnector(key="gcp-vm", display_name="Google Compute Engine virtual machine"),
        BuiltinSourceConnector(key="oci-compute", display_name="Oracle Cloud Infrastructure compute instance"),
        AwsMgnTransferAdapter(),
        AwsAmiCopyTransferAdapter(),
        DruvaTransferAdapter(),
        AwsTargetAdapter(),
        TerraformProvisioner(),
        StandardValidationAdapter(),
    ]
)
