import sys
from DotExporter import *

def edge_is_useful(edge: Edge|IncomingANDEdges, preserved_nodes: list[Node]) -> bool:
    if isinstance(edge, IncomingANDEdges):
        edges = edge
        if any([edge_is_useful(e, preserved_nodes) for e in edges]):
            return True
    else:
        if edge.src in preserved_nodes or edge.dest in preserved_nodes:
            return True
    return False


if __name__ == '__main__':
    graph = ExploitGraph()

    preserved_nodes = {
        "gaining-ama": ['alloc', 'v_dp_reg', 'dp_to_uninit', 'free', 'dp_to_free', 'dp_to_oob', 'dp_to_dangling', 'dp_to_type_confused'],
        "abusing-ama" : ['memacc_read', 'memacc_read_subst', 'memacc_read_leak', 'memacc_read_craft', 'memacc_write', 'memacc_write_subst', 'memacc_write_overwrite', 'memacc_write_leak'],
        "cf-hijack" : ['ace', 'ac_icft'],
        "data-only" : ['ac_dcft', 'disclosed_npd', 'violate_app_policy', 'leaked_npd'],
        "post-ama" : ['leaked_code', 'leaked_npd', 'ace', 'ac_icft', 'ac_dcft', 'violate_app_policy', 'disclosed_npd', 'disclosed_code']
    } [sys.argv[1]]
    preserved_nodes = [graph.nodes[n] for n in preserved_nodes] # type: ignore

    for node in graph.incoming_edges.keys():
        graph.incoming_edges[node] = [e for e in graph.incoming_edges[node] if edge_is_useful(e, preserved_nodes)] # type: ignore

    all_nodes = set[Node]()
    for n, incoming_edges in graph.incoming_edges.items():
        for edges in incoming_edges:
            if isinstance(edges, Edge):
                edges = [edges] # type: ignore
            for edge in edges:
                all_nodes.add(edge.src)
                all_nodes.add(edge.dest)

    graph.nodes = {ref: node for ref, node in graph.nodes.items() if node in all_nodes}

    export_to_file(graph, sys.argv[1], highlight_defendable=False,
        # size="3.25,5",  # (width, height)
        ratio="compress",
        fontsize="1",               
    )
