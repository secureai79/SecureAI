from dataclasses import dataclass, field


@dataclass(frozen=True)
class CapabilityIR:
    """Normalized AI capability consumed by shared risk logic."""
    agent: str | None
    ai_provider: str | None
    source: dict
    ai_controlled: bool | None
    operation: str
    target: str | None
    data_flow: list[str] = field(default_factory=list)
    confidence: float | None = None
    category: str | None = None
    language: str | None = None
