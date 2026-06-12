from ExploitGraph import *

def edgeToID(graph: ExploitGraph, edge: Edge) -> str:
    return dict[Edge, str] ({
        # first-level invalidations
        graph.find_edge('alloc', 'dp_to_uninit') : 'ptr-invalid-1',
        graph.find_edge('alloc', 'dp_to_dangling') : 'ptr-invalid-2',
        graph.find_edge('v_dp_reg', 'dp_to_oob') : 'ptr-invalid-3',
        graph.find_edge('v_dp_reg', 'dp_to_type_confused') : 'ptr-invalid-4',
        graph.find_edge('v_dp_reg', 'dp_to_free') : 'ptr-invalid-5',
        graph.find_edge('dp_to_free', 'dp_to_dangling') : 'ptr-invalid-6',
        # accessing all the first-level invalidated pointers
        graph.find_edge('dp_to_uninit', 'memacc_read') : 'ptr-invalid-7',
        graph.find_edge('dp_to_oob', 'memacc_read') : 'ptr-invalid-8',
        graph.find_edge('dp_to_oob', 'memacc_write') : 'ptr-invalid-9',
        graph.find_edge('dp_to_type_confused', 'memacc_read') : 'ptr-invalid-10',
        graph.find_edge('dp_to_type_confused', 'memacc_write') : 'ptr-invalid-11',
        graph.find_edge('dp_to_dangling', 'memacc_read') : 'ptr-invalid-12',
        graph.find_edge('dp_to_dangling', 'memacc_write') : 'ptr-invalid-13',

        # read access 
        #   leakage
        graph.find_edge('memacc_read_leak', 'conf_code_in_buffer') : 'read-abuse-1',
        graph.find_edge('memacc_read_leak', 'conf_cp_in_buffer') : 'read-abuse-2',
        graph.find_edge('memacc_read_leak', 'conf_npd_in_buffer') : 'read-abuse-3',
        graph.find_edge('memacc_read_leak', 'conf_dp_in_buffer') : 'read-abuse-4',
        #   crafting
        graph.find_edge('memacc_read_craft', 'ac_dp') : 'read-abuse-5',
        graph.find_edge('memacc_read_craft', 'malicious_ac_npd') : 'read-abuse-6',
        graph.find_edge('memacc_read_craft', 'ac_fp') : 'read-abuse-7',
        #   substitute
        graph.find_edge('memacc_read_subst', 'ac_dp') : 'read-abuse-8',
        graph.find_edge('memacc_read_subst', 'malicious_ac_npd') : 'read-abuse-9',
        graph.find_edge('memacc_read_subst', 'ac_reused_fp'): 'read-abuse-10',

        # write access 
        #   leak
        graph.find_edge('memacc_write_leak', 'conf_cp_in_buffer') : 'write-abuse-1',
        graph.find_edge('memacc_write_leak', 'conf_npd_in_buffer') : 'write-abuse-2',
        graph.find_edge('memacc_write_leak', 'conf_dp_in_buffer') : 'write-abuse-3',
        #   overwrite
        graph.find_edge('memacc_write_overwrite', 'ac_code') : 'write-abuse-4',
        graph.find_edge('memacc_write_overwrite', 'ac_ra') : 'write-abuse-5',
        graph.find_edge('memacc_write_overwrite', 'ac_fp') : 'write-abuse-6',
        graph.find_edge('memacc_write_overwrite', 'malicious_ac_npd') : 'write-abuse-7',
        graph.find_edge('memacc_write_overwrite', 'ac_dp') : 'write-abuse-8',
        #   substitute
        graph.find_edge('memacc_write_subst', 'malicious_ac_npd') : 'write-abuse-9',
        graph.find_edge('memacc_write_subst', 'ac_dp') : 'write-abuse-10',
        graph.find_edge('memacc_write_subst', 'ac_reused_fp') : 'write-abuse-11',
        graph.find_edge('memacc_write_subst', 'ac_reused_ra') : 'write-abuse-12',

        # leakage edges
        graph.find_edge('conf_code_in_buffer', 'leaked_code'): 'leakage-1',
        graph.find_edge('conf_cp_in_buffer', 'leaked_cp'): 'leakage-2',
        graph.find_edge('conf_npd_in_buffer', 'leaked_npd'): 'leakage-3',
        graph.find_edge('conf_dp_in_buffer', 'leaked_dp'): 'leakage-4',
        graph.find_edge('leaked_code', 'code_content'): 'leakage-5',
        graph.find_edge('leaked_cp', 'code_location'): 'leakage-6',
        graph.find_edge('leaked_npd', 'data_content'): 'leakage-7',
        graph.find_edge('leaked_dp', 'data_location'): 'leakage-8',

        # exploit dispatch
        graph.find_edge('ac_ra', 'fg_cfh'): 'exploit-dispatch-1',
        graph.find_edge('ac_fp', 'fg_cfh'): 'exploit-dispatch-2',
        graph.find_edge('ac_fp', 'cg_cfh'): 'exploit-dispatch-3',
        graph.find_edge('ac_ra', 'cg_cfh'): 'exploit-dispatch-4',
        graph.find_edge('ac_reused_ra', 'cg_cfh'): 'exploit-dispatch-5',
        graph.find_edge('ac_reused_fp', 'cg_cfh'): 'exploit-dispatch-6',
        graph.find_edge('malicious_ac_npd', 'ac_dcft'): 'exploit-dispatch-7',
        graph.find_edge('ac_dp', 'memacc_read'): 'exploit-dispatch-8',
        graph.find_edge('ac_dp', 'memacc_write'): 'exploit-dispatch-9',

        # exploit execution
        graph.find_edge('ac_code', 'ace') : 'exploit-execute-1',
        graph.find_edge('fg_cfh', 'ace') : 'exploit-execute-2',
        graph.find_edge('ac_fp', 'ac_pc_data') : 'exploit-execute-3',
        graph.find_edge('ac_ra', 'ac_pc_data') : 'exploit-execute-4',
        graph.find_edge('cg_cfh', 'op_control') : 'exploit-execute-5',
        graph.find_edge('ac_dcft', 'op_control') : 'exploit-execute-6',
        graph.find_edge('ac_dcft', 'violate_app_policy') : 'exploit-execute-7',
        graph.find_edge('malicious_ac_npd', 'violate_app_policy') : 'exploit-execute-8',
    }) [edge]

if __name__ == '__main__':
    graph = ExploitGraph()
    edgeToID(graph, graph.find_edge('v_dp_reg', 'dp_to_oob'))
