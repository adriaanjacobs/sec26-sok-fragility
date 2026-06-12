from Defenses import *

class TemporaryNoOp:
    def __init__(self, cls, method_names):
        self.cls = cls
        self.method_names = method_names
        self.originals = {}

    def __enter__(self):
        for name in self.method_names:
            self.originals[name] = getattr(self.cls, name)

            setattr(self.cls, name, Defenses.noop)
    def __exit__(self, exc_type, exc_val, exc_tb):
        for name, orig in self.originals.items():
            setattr(self.cls, name, orig)

def get_reached_goals(defense):
    explorer = Explorer(graph)
    defense(graph, explorer)

    if 'ReMon' in defense.__name__:
        export_to_file(graph, f'portability-{defense.__name__}', explorer, highlight_defendable=False)

    for assumed_defense in getattr(defense, 'threatmodel', []):
        # Get the method name
        name = getattr(assumed_defense, "__name__", None)
        if name is None:
            raise ValueError("Cannot determine method name for assumed_defense")
        # Look up the current method on Defenses
        method = getattr(Defenses, name)
        method(graph, explorer)
    return explorer.get_reached_goals()

if __name__ == '__main__':
    graph = ExploitGraph()

    defenses_methods = get_defense_methods()

    print(f"% {len(defenses_methods)} defenses found")

    for name, defense in defenses_methods:
        original_goals = get_reached_goals(defense)

        with TemporaryNoOp(Defenses, ['rocode', 'DEP']):
            newly_hit_goals = [g for g in get_reached_goals(defense) if g not in original_goals]
            if newly_hit_goals:
                print(f"{name}: newly reached goals: {newly_hit_goals}")






