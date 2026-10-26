from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..capability_extractor import FileAnalysis
from ..ir.capabilities import CapabilityIR


@dataclass
class LanguageAnalysis:
    language: str
    supported: bool
    file_path: str
    capabilities: list[CapabilityIR] = field(default_factory=list)
    file_analysis: FileAnalysis | None = None


class LanguageAnalyzer(ABC):
    language: str
    extensions: tuple[str, ...] = ()

    @abstractmethod
    def analyze(self, file_path: str, text: str) -> LanguageAnalysis:
        raise NotImplementedError
