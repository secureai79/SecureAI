from dataclasses import dataclass, field


@dataclass(frozen=True)
class CodeNode:
    """Language-neutral representation of a relevant code location."""
    id: str
    type: str
    file: str
    line: int | None = None
    symbol: str | None = None
    language: str | None = None
    metadata: dict = field(default_factory=dict)
