from __future__ import annotations

from abc import ABC, abstractmethod

from .models import ModuleResult, ScanContext


class ScannerModule(ABC):
    name: str
    passive: bool = True

    @abstractmethod
    def run(self, context: ScanContext) -> ModuleResult:
        """Run a scan module and return structured results."""

