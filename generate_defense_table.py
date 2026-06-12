from Defenses import *
from EdgeIDMapping import *

from typing import Callable, Any

table = R"""
\begin{table*}[t]
\centering
\caption{An overview of a broad set of unique and representative defenses, and how they map to our model.}
\label{tab:defenses}
\resizebox{.9\textwidth}{!}{%
\begin{tabular}{@{}c|c|c|c|c|ccc|ccc@{}}
\thicktoprule
\multirow{3}{*}{\makecell[c]{\textbf{\large Defense}}} &
\multirow{3}{*}{\makecell[c]{\textbf{\large Strategy}}} &
\multirow{3}{*}{\makecell[c]{\textbf{\large Category}}} &
\multirow{3}{*}{\makecell[c]{\textbf{\large Inhibited Edges}\\\textbf{\large or Knowledge}}} & 
\multirow{3}{*}{\makecell[c]{\textbf{\large Assumed Threat}\\\textbf{\large Model}}} & 
  
\multicolumn{3}{c}{\textbf{\normalsize Attacker Goals}} & 
\multicolumn{3}{c}{\textbf{\normalsize Execution Control}} \\ 
\cmidrule(lr){6-8} \cmidrule(lr){9-11}
 & & & & 
 & \makecell{Info. \\ Disclosure.} & 
 \makecell{Access \\ Control} & 
 \makecell{Arbitrary \\ Computation} & 
 \makecell{Func.-Gran.\\ CF Hijack} & 
 \makecell{Instr.-Gran.\\ CF Hijack} & 
 \makecell{ACE} \\
\thicktoprule

{sok_table_body}

\thicktoprule
\bottomrule
\end{tabular}%
}

\vspace{2pt}

\textbf{Legend:}
\smaller
\xspace \textbf{CF:} Control Flow,
\xspace \textbf{ACE:} Arbitrary Code Execution,
\xspace \textbf{MS:} Memory Safety,
\xspace \textbf{IoD:} Isolation of Data,
\xspace \textbf{IoU:} Integrity of Use,
\xspace \textbf{CLK:} Code Layout Knowledge,
\xspace \textbf{CCK:} Code Content Knowledge,
\xspace \textbf{DLK:} Data Layout Knowledge,
\xspace \textbf{UnInit:} Uninitialized pointer,
\xspace \textbf{MVX:} Multi-Variant eXecution,
\xspace \textbf{CPI:} Code Pointer Integrity,
\xspace \textbf{CFI:} Control Flow Integrity,
\xspace \textbf{DFI:} Data Flow Integrity,
\cmarkbad \xspace Attacker has achieved this goal. 

\end{table*}

"""

# Desired columns: 
# name, strategy, category, inhibited edges or knowledge, Assumed Threat Model, high-level goals reached, execution control achieved

row_template = R"""
{name}  & {strategy}  & {category} & {inhibited_edges} & {threat_model} & {data_disclose} & {access_control} & {op_control} & {cg_cfh} & {fg_cfh} & {ace} \\
"""

# generate a "compressed" ranges for the integers like
# 1-3, 5, 7-9
# for input [1, 2, 3, 5, 7, 8, 9]
def compress_int_ranges(nums): 
    nums.sort()
    ranges = []
    if nums:
        start = prev = nums[0]
        for n in nums[1:]:
            if n == prev + 1:
                prev = n
            else:
                if start == prev:
                    ranges.append(f"{start}")
                else:
                    ranges.append(f"{start}-{prev}")
                start = prev = n
        # Add the last range
        if start == prev:
            ranges.append(f"{start}")
        else:
            ranges.append(f"{start}-{prev}")
    return ranges

def defense_notation(graph: ExploitGraph, explorer: Explorer):
    edgemap = dict[str,list[int]]()
    for edge in explorer.inhibited_edges:
        desc = edgeToID(graph, edge)
        clas = "".join(desc.split('-')[:-1])
        id = desc.split('-')[-1]
        edgemap.setdefault(clas, []).append(int(id))

    notation = ""
    for (clas, ids) in edgemap.items():
        ranges = compress_int_ranges(ids)
        for range in ranges:
            notation += fR"\numcircle{clas}{{{range}}}"

    inhibited_knowledge = [n for n in graph.nodes.values() if n.type == "knowledge" and n not in explorer.initial_reached_nodes]
    notation += ",".join([fR"  \textbf{{{n.shorthand}}}" for n in inhibited_knowledge])

    return notation

def evaluate(graph, explorer, primitive: str) -> str:
    if graph.nodes[primitive] in explorer.get_reached_nodes():
        return R"\cmarkbad"
    return ""

if __name__ == '__main__':
    graph = ExploitGraph()

    defenses_methods = get_defense_methods()

    print(f"% {len(defenses_methods)} defenses found")

    sok_table_body = ""

    high_level_goals = {
        'violate_app_policy': 'Access Control', 
        'op_control' : 'Arbitrary Computation', 
        'leaked_npd' : 'Information Disclosure',
    }
    execution_control = {
        'cg_cfh' : R'\textbf{Coarse-CFH}', 
        'fg_cfh' : R'\textbf{Fine-CFH}', 
        'ace' : R'\textbf{ACE}', 
    }

    big_explorer = Explorer(graph)

    for name, func in defenses_methods:
        defense_explorer = Explorer(graph)
        func(graph, defense_explorer)
        merged_explorer = Explorer(graph)
        func(graph, merged_explorer)
        func(graph, big_explorer)

        ref = getattr(func, "citation")
        name = getattr(func, "prettyname", name)
        strategy = getattr(func, "defense_strategy", "-")
        category = getattr(func, "defense_category", "-")

        threat_explorer = Explorer(graph)
        for assumed_defense in getattr(func, 'threatmodel', []):
            if isinstance(assumed_defense, classmethod):
                assumed_defense = lambda g, e, f=assumed_defense.__func__: f(Defenses, g, e)
            assumed_defense(graph, threat_explorer)
            assumed_defense(graph, merged_explorer)
            
        attrs = {
            'name' : fR'\large {name}~\cite{{{ref}}}',
            'strategy' : fR'\large {strategy}',
            'category' : fR'\large {category}',
            'inhibited_edges' : defense_notation(graph, defense_explorer),
            'threat_model' : defense_notation(graph, threat_explorer),
            'data_disclose' : evaluate(graph, merged_explorer, 'leaked_npd'), 
            'access_control' : evaluate(graph, merged_explorer, 'violate_app_policy'), 
            'op_control' : evaluate(graph, merged_explorer, 'op_control'), 
            'cg_cfh' : evaluate(graph, merged_explorer, 'cg_cfh'), 
            'fg_cfh' : evaluate(graph, merged_explorer, 'fg_cfh'), 
            'ace' : evaluate(graph, merged_explorer, 'ace'), 
        }
        sok_table_body += '\midrule \n'
        sok_table_body += row_template.format(**attrs)

    table = table.replace('{sok_table_body}', sok_table_body)

    print(table)

    print(f"% In total, this table covers {len(big_explorer.inhibited_edges)} unique edges and {len([n for n in graph.nodes.values() if n.type == 'knowledge' and n not in big_explorer.initial_reached_nodes])} types of knowledge")
    print(f"% merged defense notation: {defense_notation(graph, big_explorer)}")
