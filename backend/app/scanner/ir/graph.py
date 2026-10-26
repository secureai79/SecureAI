from dataclasses import dataclass, field
from .nodes import CodeNode
from .edges import CodeEdge


@dataclass
class CodeGraph:
    nodes: dict[str, CodeNode] = field(default_factory=dict)
    edges: list[CodeEdge] = field(default_factory=list)

    def add_node(self, node: CodeNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: CodeEdge) -> None:
        self.edges.append(edge)
