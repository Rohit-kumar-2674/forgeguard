from __future__ import annotations

from abc import ABC, abstractmethod

from forgeguard.models import Finding, ScanContext


class Check(ABC):
    """Stable interface for independently testable ForgeGuard checks."""

    check_id: str
    name: str
    category: str

    @abstractmethod
    def run(self, context: ScanContext) -> list[Finding]:
        raise NotImplementedError

