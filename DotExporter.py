from Explorer import *

from typing import Optional
from graphviz import Digraph # type: ignore
import itertools

# mypy: check_untyped_defs=True


def wrap_label(label, width):
    """
    Wraps the label text to the specified width, splitting into an arbitrary number of lines.
    Ensures words are not split and minimizes slack (wasted space at the end of lines).

    Args:
        label: The text to wrap.
        width: The maximum width of each line.

    Returns:
        A string with the label wrapped into multiple lines.
    """
    words = label.split()
    if not words:
        return label  # Handle empty labels

    # Start by putting each word on a separate line
    lines = [[word] for word in words]

    # Try to merge lines while minimizing slack
    merged = []
    current_line = lines[0]
    for next_line in lines[1:]:
        # Check if merging the next word into the current line exceeds the width
        if len(" ".join(current_line + next_line)) <= width:
            current_line += next_line  # Merge the lines
        else:
            merged.append(current_line)  # Finalize the current line
            current_line = next_line  # Start a new line
    merged.append(current_line)  # Add the last line

    # Convert lines back to strings and minimize slack
    wrapped_lines = [" ".join(line) for line in merged]
    return "\n".join(wrapped_lines)

class EdgeAttributes:
    def __init__(self, is_defensible : bool, label: Optional[str] = "", is_inhibited : bool = False):
        self.is_defensible = is_defensible
        self.label = wrap_label(label, 10)
        self.is_inhibited = is_inhibited

def draw_edge(dot: Digraph, src: Node, dest: Node|str, attr: EdgeAttributes):
    if isinstance(dest, Node):
        destname = dest.ref
    else:
        destname = dest

    # Explicitly set tailport and headport for dummy nodes
    tailport = None
    arrowtail : Optional[str] ='dot'
    dir : Optional[str] ="both"
    if src.type == "dummy":
        tailport = 's'
        arrowtail = None
        dir = None
    headport = 'n' if dest == "dummy" else None

    color = 'black'
    penwidth = 1

    if attr.is_defensible:
        penwidth = 3
        color = 'blue'

    if attr.is_inhibited:
        color = 'red'
        penwidth = 3
        attr.label = f"🛡️ {attr.label}"
        if attr.label.rstrip() != "🛡️":
            attr.label = f"{attr.label} 🛡️"

    weight = "10" if attr.label in ["reg->mem", "mem->reg"] else None

    dot.edge(src.ref, destname, 
        tailport=tailport,
        headport=headport,
        arrowtail = arrowtail, dir = dir,
        label = attr.label,
        weight = weight,
        color = color,
        penwidth=str(penwidth)
    )

def draw_and_gate(dot: Digraph, edges: list[tuple[Edge, EdgeAttributes]], resultlabel: Optional[str]):
    # Generate a unique gate name based on input and output references
    output = edges[0][0].dest
    input_refs = "_and_".join(input_node.ref for input_node in [e[0].src for e in edges])
    gate_name = f"{input_refs}_yields_{output.ref}"

    # Add the AND gate node
    dot.node(gate_name, label="AND", shape="invhouse")

    # Add edges from inputs to the AND gate
    for edge, attrs in edges:
        draw_edge(dot, edge.src, gate_name, attrs)

    # Add an edge from the AND gate to the output
    if resultlabel:
        resultlabel = wrap_label(resultlabel, 16)
    dot.edge(gate_name, output.ref, label = resultlabel, tailport="s")

def export_to_file(graph: ExploitGraph, filename: str, explorer : Optional[Explorer] = None, highlight_defendable = True, **dot_attrs):
    dot = Digraph()
    dot.attr(
        **dot_attrs,
        splines='polyline',
    )

    added_duplicate_nodes = dict[Node, Node]()
    def generate_duplicate_node(src: Node, destname: str) -> Node:
        original = src
        src = src.__copy__()        
        src.ref = f"{src.ref}_duplicate_for_{destname}"
        if src.type == "knowledge": # compress the names of the duplicates
            src.label = "".join([s[0].upper() for s in src.label.split()])
        added_duplicate_nodes[src] = original
        return src
    
    # place all edges
    for dest, incoming_edge_sets in graph.incoming_edges.items():
        for incoming in incoming_edge_sets:
            if isinstance(incoming, IncomingANDEdges):
                assert len(incoming) > 1
                src_nodes = [e.src for e in incoming]
                src_nodes = [n if n.type not in ["knowledge", "entrypoint"] else generate_duplicate_node(n, dest.ref) for n in src_nodes]

                def edge_is_inhibited(src: Node):
                    if not explorer:
                        return False
                    if src in added_duplicate_nodes:
                        src = added_duplicate_nodes[src]
                    for e in incoming:
                        if e.src == src:
                            return explorer.edge_inhibited(e)
                    raise Exception()
                
                def edge_is_defensible(src: Node):
                    if src in added_duplicate_nodes:
                        src = added_duplicate_nodes[src]
                    for e in incoming:
                        if e.src == src:
                            return e.is_defendable
                    raise Exception()

                edges = [(Edge(src, dest), EdgeAttributes(edge_is_defensible(src) and highlight_defendable, is_inhibited = edge_is_inhibited(src))) for src in src_nodes]
                draw_and_gate(dot, edges, incoming.resultlabel)
            else:
                assert incoming.src.type not in ["knowledge"] # knowledge alone should never directly lead to other capabilities
                draw_edge(dot, incoming.src, incoming.dest, EdgeAttributes(incoming.is_defendable and highlight_defendable, incoming.label, is_inhibited=explorer.edge_inhibited(incoming) if explorer else False))

    def is_node_reached(node: Node, explorer: Explorer):
        if node in added_duplicate_nodes:
            node = added_duplicate_nodes[node]
        return node in explorer.get_reached_nodes()

    # place all nodes
    for node in itertools.chain(graph.nodes.values(), added_duplicate_nodes.keys()):
        # outgoing edges got duplicated, no ingoing edges: skip
        if node in added_duplicate_nodes.values() and (node not in graph.incoming_edges or len(graph.incoming_edges[node]) == 0):
            continue

        node_reached = is_node_reached(node, explorer) if explorer else False

        stroke_color, stroke_width = node.strokeattr(node_reached)
        dot.node(node.ref, label=wrap_label(node.label, width=15), 
            shape=node.shape(), fixedsize='false', 
            style='filled', fillcolor=node.color(),
            color=stroke_color, penwidth=stroke_width
        )

    # Render the graph as an SVG file
    format = 'svg'
    dot.render(filename, format=format, cleanup=True)
    print(f"Dumped graph to '{filename}.{format}'")


if __name__ == '__main__':
    graph = ExploitGraph()
    export_to_file(graph, 'graph', highlight_defendable=False)
