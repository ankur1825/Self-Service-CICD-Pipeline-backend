from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable


class MigrationProviderAdapter(ABC):
    provider: str

    @abstractmethod
    def capabilities(self) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def build_plan(self, project: Any, wave: Any, workloads: Iterable[Any], environment: Any) -> Dict[str, Any]:
        raise NotImplementedError
