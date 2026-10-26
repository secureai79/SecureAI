from dataclasses import dataclass, field


@dataclass(frozen=True)
class CodeEdge:
    """Language-neutral data/control-flow relationship."""
    source: str
    target: str
    edge_type: str
    metadata: dict = field(default_factory=dict)
