from __future__ import annotations  # For forward references in type hints (Python < 3.9)
from ExploitGraph import *
from typing import Iterable, Optional

# mypy: check_untyped_defs=True

class Explorer:
    def __init__(self, graph: ExploitGraph, reached_nodes : Iterable[Node] = []):
        self._graph = graph
        self.initial_reached_nodes = set[Node]()
        self.__reached_nodes = set[Node]()
        self.inhibited_edges = dict[Edge, bool|str]() # map of edge to predicate. True = no predicate
        self.__reached_nodes_up_to_date = False
        self.predicates = dict[str, bool]()

        # default reached nodes
        #   all entrypoints & dummy nodes without incoming edges
        for n in self._graph.nodes.values():
            # all entrypoints
            if n.type == "entrypoint":
                self.mark_reached_initial(n)
            # all dummy nodes without incoming edges
            if n not in graph.incoming_edges.keys():
                assert n.type in ["dummy", "entrypoint"]
                self.mark_reached_initial(n)
            # all knowledge
            if n.type == "knowledge":
                self.mark_reached_initial(n)

        # user-requested initial reached nodes
        for n in reached_nodes:
            self.mark_reached_initial(n)

    @classmethod
    def from_existing(self, other: Explorer) -> Explorer:
        """Create a lightweight copy of an existing Explorer instance."""
        # Create an uninitialized instance
        new_instance = self.__new__(self)
        # Manually copy attributes
        new_instance._graph = other._graph
        new_instance.initial_reached_nodes = other.initial_reached_nodes.copy()
        new_instance.__reached_nodes_up_to_date = False
        new_instance.inhibited_edges = other.inhibited_edges.copy()
        new_instance.predicates = other.predicates.copy()
        return new_instance        
    
    def copy(self) -> Explorer:
        return Explorer.from_existing(self)
    
    def update_initial_nodes(self, nodes: Iterable[Node]) -> None:
        self.initial_reached_nodes.update(nodes)
        self.__reached_nodes_up_to_date = False
    
    def get_affecting_predicates(self):
        ret = set[str]()
        for predicate in self.inhibited_edges.values():
            if isinstance(predicate, str):
                ret.add(predicate)
        return ret
    
    def find_unassigned_predicate(self):
        for pred in self.inhibited_edges.values():
            if isinstance(pred, str) and not pred.startswith("not") and pred not in self.predicates:
                return pred
        return None
    
    def enumerate_predicate_combinations(self):
        pred = self.find_unassigned_predicate()
        if pred is None:
            yield self.predicates
            return
        
        self.predicates[pred] = True
        self.__reached_nodes_up_to_date = False
        yield from self.enumerate_predicate_combinations()
        self.predicates[pred] = False
        self.__reached_nodes_up_to_date = False
        yield from self.enumerate_predicate_combinations()
        del self.predicates[pred]
        self.__reached_nodes_up_to_date = False
    
    def mark_reached_initial(self, node : Node):
        self.initial_reached_nodes.add(node)
        self.__reached_nodes_up_to_date = False

    def mark_not_reached_initial(self, node : Node):
        if node in self.initial_reached_nodes:
            self.initial_reached_nodes.remove(node)
            self.__reached_nodes_up_to_date = False   

    def node_reached(self, node: Node):
        self.update_reached_nodes()
        return node in self.__reached_nodes
    
    def inhibit(self, *edges: Edge|Node):
        self.inhibit_predicated(True, *edges)

    def inihibit_all_edges_from(self, *nodes: Node|str):
        for n in nodes:
            if isinstance(n, str):
                n = self._graph.nodes[n]
        
        for _, incoming_edges in self._graph.incoming_edges.items():
            for edges in incoming_edges:
                if isinstance(edges, Edge):
                    edges = [edges] # type: ignore
                for edge in edges:
                    if edge.is_defendable and edge.src in nodes:
                        self.inhibit(edge)

    def inihibit_all_edges_to(self, *nodes: Node|str):
        for n in nodes:
            if isinstance(n, str):
                n = self._graph.nodes[n]
            incoming_edges = self._graph.incoming_edges[n]
            for edges in incoming_edges:
                if isinstance(edges, Edge):
                    edges = [edges] # type: ignore
                for edge in edges:
                    if edge.is_defendable:
                        self.inhibit(edge)

    def inhibit_predicated(self, predicate: str|bool, *edges: Edge|Node):
        self.__reached_nodes_up_to_date = False
        for edge in edges:
            if isinstance(edge, Edge):
                assert edge.is_defendable
                self.inhibited_edges[edge] = predicate
            else:
                assert isinstance(edge, Node)
                assert edge.type == "knowledge"
                self.mark_not_reached_initial(edge)

    def uninhibit(self, *edges: Edge):
        self.__reached_nodes_up_to_date = False
        for edge in edges:
            if edge in self.inhibited_edges:
                del self.inhibited_edges[edge]

    def evaluate_predicate(self, predicate: bool|str) -> bool:
        if isinstance(predicate, bool):
            return predicate
        negated =  predicate.startswith("not ")
        predicate = predicate.strip("not ")
        if predicate in self.predicates:
            return self.predicates[predicate] if not negated else not self.predicates[predicate]
        raise Exception(f"predicate '{predicate}' not assigned")

    def edge_inhibited(self, edge: Edge):
        if edge not in self.inhibited_edges:
            return False
        predicate = self.inhibited_edges[edge]
        return self.evaluate_predicate(predicate)

    def incoming_edge_reached(self, edge) -> bool:
        if isinstance(edge, IncomingANDEdges):
            return all([self.incoming_edge_reached(e) for e in edge])
        else:
            return not self.edge_inhibited(edge) and edge.src in self.__reached_nodes

    def get_reached_nodes(self):
        # check if the cache was invalidated
        if self.__reached_nodes_up_to_date:
            return self.__reached_nodes
        
        # ok, we have to recompute
        self.__reached_nodes = self.initial_reached_nodes.copy()
        size = 0
        worklist = [n for n in self._graph.nodes.values() if not n in self.__reached_nodes]
        while size != len(worklist):
            size = len(worklist)
            for node in worklist:
                if any([self.incoming_edge_reached(e) for e in self._graph.incoming_edges.get(node, [])]):
                    worklist.remove(node)
                    self.__reached_nodes.add(node)
        
        self.__reached_nodes_up_to_date = True
        return self.__reached_nodes
    
    def update_reached_nodes(self):
        self.get_reached_nodes()

    def get_reached_goals(self):
        return [n for n in self.get_reached_nodes() if n.type == 'goal']
