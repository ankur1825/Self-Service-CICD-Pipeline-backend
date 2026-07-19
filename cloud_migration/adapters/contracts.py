from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, Sequence


class AdapterExecutionLocked(RuntimeError):
    """Raised when an adapter is asked to mutate infrastructure before execution is enabled."""


@dataclass(frozen=True)
class AdapterCapability:
    key: str
    kind: str
    display_name: str
    adapter_version: str
    status: str
    source_types: Sequence[str] = ()
    target_providers: Sequence[str] = ()
    strategies: Sequence[str] = ()
    required_entitlements: Sequence[str] = ()
    execution_mode: str = "client-hosted"
    execution_enabled: bool = False
    license_mode: str = "included"
    recommended: bool = False
    unavailable_reason: str | None = None

    def supports(self, source_type: str, target_provider: str, strategy: str | None = None) -> bool:
        if self.source_types and source_type not in self.source_types:
            return False
        if self.target_providers and target_provider not in self.target_providers:
            return False
        if strategy and self.strategies and strategy not in self.strategies:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        for key in ("source_types", "target_providers", "strategies", "required_entitlements"):
            result[key] = list(result[key])
        return result


class MigrationAdapter(ABC):
    @abstractmethod
    def capabilities(self) -> AdapterCapability:
        raise NotImplementedError


class SourceConnector(MigrationAdapter):
    def discover(self, context: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
        raise AdapterExecutionLocked("Source discovery requires a configured client-hosted execution worker.")

    def validate_access(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise AdapterExecutionLocked("Source access validation requires a configured client-hosted execution worker.")


class TransferAdapter(MigrationAdapter):
    def preflight(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise AdapterExecutionLocked("Transfer preflight requires a configured client-hosted execution worker.")

    def start_replication(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise AdapterExecutionLocked("Replication is locked until client-hosted execution and approvals are enabled.")

    def reconcile(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise AdapterExecutionLocked("Replication reconciliation requires a configured client-hosted execution worker.")


class TargetProviderAdapter(MigrationAdapter):
    def validate_target(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise AdapterExecutionLocked("Target validation requires a configured client-hosted execution worker.")

    def launch_test(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise AdapterExecutionLocked("Test launch is locked until client-hosted execution and approvals are enabled.")


class InfrastructureProvisioner(MigrationAdapter):
    def plan(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise AdapterExecutionLocked("Infrastructure planning requires a configured client-hosted execution worker.")

    def apply(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise AdapterExecutionLocked("Infrastructure changes are locked until client-hosted execution and approvals are enabled.")


class ValidationAdapter(MigrationAdapter):
    def validate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise AdapterExecutionLocked("Workload validation requires a configured client-hosted execution worker.")
