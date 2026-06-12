# SoK: On the Fragility of Memory Error Exploit Mitigations

This repository implements a graph model for memory error exploitation, as described in our USENIX'26 paper. 
```bibtex
@inproceedings{jacobs2026sokfragility,
  title={{SoK:} On the Fragility of Memory Error Exploit Mitigations},
  author={Jacobs, Adriaan and Ammar, Mahmoud and Volckaert, Stijn},
  booktitle={Proceedings of the 35th USENIX Security Symposium (USENIX Security 2026)},
  year={2026},
  publisher={USENIX Association}
}
```

## Overview

*   **`ExploitGraph.py`**: Defines the model. 
*   **`Explorer.py`**: Utility class that tracks inhibited knowledge and edges, and computes reachability queries over an ExploitGraph. 
*   **`Defenses.py`**: Contains the list of modeled defenses on the graph, as methods that apply inhibitions to an Explorer instance. 

To evaluate the fragility of a modeled defense or set of defenses, use
```bash
python3 Defenses.py fragility SoftBound_wo
```

To evaluate the interoperability of two sets of defenses, use
```bash
python3 Defenses.py interop --set1 Rust --set2 FineIBT intelSHSTK
```

## Paper Reproduction Scripts
*   **`generate_defense_table.py`**: Iterates through all defenses defined in `Defenses.py` and evaluates their effectiveness. It outputs Table 4 from the paper. 
*   **`portability_test.py`**: Tests the fragility and platform-independence of the modeled defenses by temporarily disabling foundational, assumed protections (like `DEP` or read-only code) and observing if new attack vectors open up. Described in Section 6.2 of the paper. 
*   **`cla_generation.py`**: Performs the interoperability evaluation described in Section 6.1 of the paper, between minimal first-level defense sets and Safe Rust. 
