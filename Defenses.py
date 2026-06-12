# Usage to map defenses:
"""
@staticmethod
@citation("authorYEARname")
def defense_name(graph: ExploitGraph, explorer: Explorer):
    explorer.inhibit(
        graph.find_edge(),
    )
"""

import sys
import argparse
from DotExporter import *
from typing import Callable

def citation(ref):
    def decorator(func):
        func.citation = ref
        return func
    return decorator

def threatmodel(ref):
    def decorator(func):
        func.threatmodel = ref
        return func
    return decorator

def prettyname(ref):
    def decorator(func):
        func.prettyname = ref
        return func
    return decorator

def defense_strategy(ref):
    def decorator(func):
        func.defense_strategy = ref
        return func
    return decorator

def defense_category(ref):
    def decorator(func):
        func.defense_category = ref
        return func
    return decorator


class Defenses:
    @staticmethod
    def noop(graph, explorer):
        pass

    @staticmethod
    def no_miscasts(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(graph.find_edge('v_dp_reg', 'dp_to_type_confused'))

    @staticmethod
    def no_spatial(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(graph.find_edge('v_dp_reg', 'dp_to_oob'))

    @staticmethod
    def no_temporal(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(graph.find_edge('v_dp_reg', 'dp_to_free'))

    @staticmethod
    def no_uninit(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(graph.find_edge('alloc', 'dp_to_uninit'))

    @staticmethod
    def codeASLR(graph: ExploitGraph, explorer: Explorer):
        code_loc_knowledge = graph.nodes['code_location']
        explorer.mark_not_reached_initial(code_loc_knowledge)

    @staticmethod
    def dataASLR(graph: ExploitGraph, explorer: Explorer):
        data_loc_knowledge = graph.nodes['data_location']
        explorer.mark_not_reached_initial(data_loc_knowledge)

    @staticmethod
    def DEP(graph: ExploitGraph, explorer : Explorer):
        # data execution not possible
        explorer.inhibit(graph.find_edge('ac_ra', 'ac_pc_data'))
        explorer.inhibit(graph.find_edge('ac_fp', 'ac_pc_data'))
    
    @staticmethod
    def rocode(graph: ExploitGraph, explorer : Explorer):
        explorer.inhibit(graph.find_edge('memacc_write_overwrite', 'ac_code'))

    @staticmethod
    def no_backward_edge(graph: ExploitGraph, explorer: Explorer):
        # inhibit all ways to obtain ac ra
        explorer.inihibit_all_edges_to('ac_ra', 'ac_reused_ra')

    @staticmethod
    def no_forward_edge(graph: ExploitGraph, explorer: Explorer):
        # inhibit all ways to obtain ac fp
        explorer.inihibit_all_edges_to('ac_fp', 'ac_reused_fp')

    @classmethod
    def no_control_data(self, graph: ExploitGraph, explorer: Explorer):
        # inhibit all invalid memaccesses to control data
        self.no_backward_edge(graph, explorer)
        self.no_forward_edge(graph, explorer)

    @staticmethod
    @citation("matsakis2014Rust")
    @prettyname("Safe Rust")
    @defense_strategy("MS")
    @defense_category("Complete")
    def Rust(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_free'),    # no pointer to free can ever exist
            graph.find_edge('v_dp_reg', 'dp_to_type_confused'), # strongly typed
            graph.find_edge('v_dp_reg', 'dp_to_oob'),        # not allowed to create arithmetic-d pointer
                                                             # tbf you are allowed to create it, just not to dereference it anymore (even after bringing it back)
                                                             # it's not really a pointer at that point anymore though. Although you could still pass it to external code
                                                             # this is def a judgement call, highlights a limitation of the model
            graph.find_edge('alloc', 'dp_to_uninit'),        # not allowed to create references to uninitialized memory
        )

    @staticmethod
    @citation("necula2005CCured")
    @prettyname("CCured")
    @defense_strategy("MS")
    @defense_category("Complete")
    def CCured(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.find_edge('dp_to_oob', 'memacc_write'),       # fat pointers for spatial
            graph.find_edge('dp_to_oob', 'memacc_read'),
            graph.find_edge('alloc', 'dp_to_uninit'),           # auto-initialization for uninit
            graph.find_edge('v_dp_reg', 'dp_to_free'),    # garbage collection for temporal
            graph.find_edge('v_dp_reg', 'dp_to_type_confused')  # cast checks
        )
 
    @staticmethod
    @citation("softbound")
    @prettyname("SoftBound")
    @defense_strategy("MS")
    @defense_category("Spatial")
    @threatmodel([no_uninit,no_miscasts,no_temporal])
    def SoftBound(graph: ExploitGraph, explorer : Explorer, write_only: bool = False):
        # oob accesses are stopped
        explorer.inhibit(graph.find_edge('dp_to_oob', 'memacc_write'))
        if not write_only:
            explorer.inhibit(graph.find_edge('dp_to_oob', 'memacc_read'))

        # SoftBound's "shadow pointer store" happens to implement an additional pointer integrity mechanism:
        #   by default, SoftBound rejects metadata loads from non-pointer-holdings locations

        # crafting data pointers is impossible
        explorer.inhibit(
            graph.find_edge('memacc_read_craft', 'ac_dp'),      # reading from non-pointer-data would not preserve pointer-ness
        )
        
        # crafting function pointers is impossible
        explorer.inhibit(
            graph.find_edge('memacc_read_craft', 'ac_fp'),      # reading from non-pointer-data would not preserve pointer-ness
        )

        # the model doesn't currently cover "reused data pointers"
        #   we still exclude some "illegitimate targets" from ac_dp overwrites
        explorer.inhibit(
            graph.find_edge('memacc_write_overwrite', 'ac_ra')
        )

        # SoftBound includes checks on indirect branches that the target is truthfully a registered function pointer
        explorer.inhibit(
            graph.find_edge('ac_fp', 'ac_pc_data'), # not a valid func entry
            graph.find_edge('ac_fp', 'fg_cfh')      # not a valid func entry
        )
        
    @classmethod
    @citation("softbound")
    @prettyname("SoftBound-w.o.")
    @defense_strategy("MS")
    @defense_category("Spatial")
    @threatmodel([no_uninit,no_miscasts,no_temporal])
    def SoftBound_wo(self, graph: ExploitGraph, explorer : Explorer):
        self.SoftBound(graph, explorer, True)

    # obvious edge fragility cases here
    @staticmethod
    @citation("stickytags")
    @prettyname("StickyTags")
    @defense_strategy("MS")
    @defense_category("Spatial")
    @threatmodel([no_uninit,no_miscasts,no_temporal])
    def StickyTags(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.find_edge('dp_to_oob', 'memacc_write'),
            graph.find_edge('dp_to_oob', 'memacc_read'),
        )

    @staticmethod    
    @citation("duck2016heap")
    @prettyname("LowFat")
    @defense_strategy("MS")
    @defense_category("Spatial")
    @threatmodel([no_uninit,no_miscasts,no_temporal])
    def LowFat(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_oob'),
        )

    @classmethod
    @citation("effectivesan")
    @prettyname("EffectiveSan")
    @defense_strategy("MS")
    @defense_category("Spatial, Temporal, Miscasts")
    @threatmodel([no_uninit])
    def EffectiveSan(self, graph: ExploitGraph, explorer: Explorer):
        self.EffectiveSan_type(graph, explorer)
        self.EffectiveSan_bounds(graph, explorer)
        explorer.inhibit(
            graph.find_edge('dp_to_dangling', 'memacc_read'),
            graph.find_edge('dp_to_dangling', 'memacc_write'),
        )

    @staticmethod
    @citation("effectivesan")
    @prettyname("EffectiveSan-bounds")
    @defense_strategy("MS")
    @defense_category("Spatial")
    @threatmodel([no_uninit,no_miscasts,no_temporal])
    def EffectiveSan_bounds(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_oob'),           # lowfat for spatial
        )

    @staticmethod
    @citation("effectivesan")
    @prettyname("EffectiveSan-type")
    @defense_strategy("MS")
    @defense_category("Miscasts")
    @threatmodel([no_uninit,no_spatial,no_temporal])
    def EffectiveSan_type(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.find_edge('dp_to_type_confused', 'memacc_read'),
            graph.find_edge('dp_to_type_confused', 'memacc_write'),
        )

    # typepp is the same. I think typesan, CaVer, and Bitype too 
    @staticmethod
    @citation("hextype")
    @prettyname("HexType")
    @defense_strategy("MS")
    @defense_category("Miscasts")
    @threatmodel([no_uninit,no_spatial,no_temporal])
    def HexType(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(graph.find_edge('v_dp_reg', 'dp_to_type_confused'))

    # debugging tool, same protection as EffectiveSan-type anyway
    # @staticmethod
    # @citation("llvm2017TySan")
    # def TySan(graph: ExploitGraph, explorer : Explorer):
    #     explorer.inhibit(
    #         graph.find_edge('dp_to_type_confused', 'memacc_read'),
    #         graph.find_edge('dp_to_type_confused', 'memacc_write'),
    #     )
    
    @staticmethod
    @citation("li2022PACMem")
    @prettyname("PACMem")
    @defense_strategy("MS")
    @defense_category("Spatial, Temporal")
    @threatmodel([no_uninit,no_miscasts])
    def PACMem(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.find_edge('dp_to_oob', 'memacc_read'),
            graph.find_edge('dp_to_oob', 'memacc_write'),
            graph.find_edge('dp_to_dangling', 'memacc_read'),
            graph.find_edge('dp_to_dangling', 'memacc_write'),
        )

    # Lock&Key. Undangle is the same here
    @staticmethod
    @citation("nagarakatte2010CETS")
    @prettyname("CETS")
    @defense_strategy("MS")
    @defense_category("Temporal")
    @threatmodel([no_spatial,no_miscasts,no_uninit])
    def CETS(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.find_edge('dp_to_dangling', 'memacc_read'),
            graph.find_edge('dp_to_dangling', 'memacc_write'),
        )
        # crafting data pointers is impossible due to shadow memory
        explorer.inhibit(
            graph.find_edge('memacc_write_overwrite', 'ac_dp'), # writing from non-pointer-data would not preserve pointer-ness
            graph.find_edge('memacc_read_craft', 'ac_dp'),      # reading from non-pointer-data would not preserve pointer-ness
        )

    # eliminate pointers to free: FreeSentry & DangNull too. Oscar too?
    @staticmethod
    @citation("vanderkouwe2017DangSan")
    @prettyname("DangSan")
    @defense_strategy("MS")
    @defense_category("Temporal")
    @threatmodel([no_spatial,no_miscasts,no_uninit])
    def DangSan(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_free'),
        )
    
    # garbage collection: delay memory reuse until no more free pointers exist
    #   also: I think dhurjati's server thing, pSweeper, CRCount
    @staticmethod
    @citation("ainsworth2020markus")
    @prettyname("MarkUs")
    @defense_strategy("MS")
    @defense_category("Temporal")
    @threatmodel([no_spatial,no_miscasts,no_uninit])
    def MarkUs(graph: ExploitGraph, explorer: Explorer):
        # pointers to free memory cannot be turned into dangling pointers
        #   because memory reuse will be delayed until they disappear from the program
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_free'),
        )

    # one-time allocation
    @staticmethod
    @citation("wickman2021ffmalloc")
    @prettyname("FFMalloc")
    @defense_strategy("MS")
    @defense_category("Temporal")
    @threatmodel([no_spatial,no_miscasts,no_uninit])
    def FFMalloc(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.find_edge('alloc', 'dp_to_dangling'),
            # no memory reuse also means that there can be no uninitialized reads
            graph.find_edge('alloc', 'dp_to_uninit'),
        )

    # memory zeroing on alloc
    @staticmethod
    @citation("milburn2017safeinit")
    @prettyname("SafeInit")
    @defense_strategy("MS")
    @defense_category("Uninitialized")
    @threatmodel([no_spatial,no_miscasts,no_temporal])
    def SafeInit(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(graph.find_edge('alloc', 'dp_to_uninit'))

    # memory zeroing on free
    @staticmethod
    @citation("chow2005shredding")
    @prettyname("Chow et al.")
    @defense_strategy("MS")
    @defense_category("Uninitialized")
    @threatmodel([no_spatial,no_miscasts,no_temporal])
    def chow2005shredding(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(graph.find_edge('alloc', 'dp_to_uninit'))

    @staticmethod
    @citation("woodruff2014cheri")
    @prettyname("CHERI")
    @defense_strategy("MS, IoD, IoU")
    @defense_category("Spatial")
    @threatmodel([no_temporal,no_uninit,no_miscasts])
    def CHERI(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.find_edge('dp_to_oob', 'memacc_write'),
            graph.find_edge('dp_to_oob', 'memacc_read'),
        )

        # in addition to regular bounds checking, CHERI also prohibits pointer crafting:
        #   only intentional pointer/capability-holding operations can overwrite or read pointers
        # or, at least, reading and writing capabilities using non-capability instructions is allowed,
        #   it just destroys the capability in the process
        explorer.inhibit(
            graph.find_edge('memacc_write_overwrite', 'ac_dp'), # overwriting dp with npd does not yield usable ac_dp
            graph.find_edge('memacc_read_craft', 'ac_dp'),      # reading a non-capability into a capability register is allowed, but does not yield a valid capability
            # same things for code pointers
            graph.find_edge('memacc_write_overwrite', 'ac_fp'),
            graph.find_edge('memacc_write_overwrite', 'ac_ra'),
            graph.find_edge('memacc_read_craft', 'ac_fp'),
        )

        # data pointers can never point to code
        explorer.inhibit(
            graph.find_edge('memacc_write_overwrite', 'ac_code'),
        )

        # code pointers can never point to data
        explorer.inhibit(
            graph.find_edge('ac_ra', 'ac_pc_data'),
            graph.find_edge('ac_fp', 'ac_pc_data'),
        )

    # "informed' garbage collection -- sped up with revocation
    @staticmethod
    @citation("filardo2020cornucopia")
    @prettyname("Cornucopia")
    @defense_strategy("MS")
    @defense_category("Temporal")
    @threatmodel([CHERI,no_uninit,no_miscasts])
    def Cornucopia(graph: ExploitGraph, explorer: Explorer):
        # concurrent thread scans memory, revokes capabilities to free memory
        #   memory reuse delayed until all capabilities revoked
        # we can just see the 'revocation' as a speedup for garbage allocation
        #   (which just waits until they naturally disappear)
        # if it was not parallel, it would be much more like DangSan
        #   effect of optimization on modeling!
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_free'),
        )

    # detect uninitialized read
    @staticmethod
    @citation("gulmez2025moncheri")
    @prettyname(R"Mon CH{\'E}RI")
    @defense_strategy("MS")
    @defense_category("Uninitialized")
    @threatmodel([CHERI,Cornucopia,no_miscasts])
    def MonCheri(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(graph.find_edge('dp_to_uninit', 'memacc_read'))

    @classmethod
    @citation("ye2025wxorx")
    @prettyname(R"$W\oplus X$")
    @defense_strategy("IoD,IoU")
    @defense_category("-")
    def WxorX(self, graph: ExploitGraph, explorer : Explorer):
        self.DEP(graph, explorer)
        self.rocode(graph, explorer)

    @staticmethod
    def no_invalid_writes(graph: ExploitGraph, explorer : Explorer):
        explorer.inihibit_all_edges_from('memacc_write_subst')
        explorer.inihibit_all_edges_from('memacc_write_leak')
        explorer.inihibit_all_edges_from('memacc_write_overwrite')

    @staticmethod
    def no_invalid_reads(graph: ExploitGraph, explorer : Explorer):
        explorer.inihibit_all_edges_from('memacc_read_subst')
        explorer.inihibit_all_edges_from('memacc_read_leak')
        explorer.inihibit_all_edges_from('memacc_read_craft')

    @classmethod
    @citation("wit")
    @prettyname("WIT")
    @defense_strategy("IoD, IoU")
    @defense_category("DFI")
    def WIT(self, graph: ExploitGraph, explorer : Explorer):
        # static PTS allowlisting on writes
        self.no_invalid_writes(graph, explorer)
        # additional IoU protection on data pointers
        #   due to static evidence
        explorer.inhibit(
            graph.find_edge('ac_dp', 'memacc_write')
        )

        # + additional fine-grained forward-edge CFI
        explorer.inhibit(            # indirect branch checking only applies to function pointers
            graph.find_edge('ac_fp', 'cg_cfh'),
            graph.find_edge('ac_fp', 'fg_cfh'),
            graph.find_edge('ac_fp', 'ac_pc_data'),
            graph.find_edge('ac_reused_fp', 'cg_cfh'),
        )

    @classmethod
    @citation("bhatkar2008DSR,cadar2008DR")
    @prettyname("DSR")
    @defense_strategy("IoD")
    @defense_category("Data Randomization")
    def DSR(self, graph: ExploitGraph, explorer: Explorer):
        # inhibit all invalid reads -> without edge fragility, they target a different equivalence class
        self.no_invalid_reads(graph, explorer)

        # inhibit all invalid writes -> same reason
        self.no_invalid_writes(graph, explorer)

    @classmethod
    @citation("castrodfi")
    @prettyname("DFI")
    @defense_strategy("IoD, IoU")
    @defense_category("DFI")
    def DFI(self, graph: ExploitGraph, explorer : Explorer):
        # most writes are allowed, unrestricted

        # reads are checked for validity: invalid reads would read data that was not written by
        #   a permitted write instruction
        self.no_invalid_reads(graph, explorer)

        # corrupted data, even when benignly read, likely triggers a use violation
        #   all potential write targets cannot be used
        #   these write targets _could_ also have been invalid read targets
        #   (in which case the protection would not apply)
        #   but because all invalid reads are already stopped, they could only have originated
        #   from an invalid write
        # we can be comprehensive here, because all corrupted data sits in memory, and must be
        # loaded to be used. There could technically be non-instrumented or external loads,
        #  but they instrument pointer arguments to external functions for this reason
        #  they don't seem to instrument returns into callers though!
        # The only two cases where we could watch out are:
        #   usage of corrupted RAs (won't explicitly be read): they explicitly instrument returns
        #   usage of corrupted code (won't excplitily be read): they say the following about this:
        #       " Code tampering can be prevented [by instrumenting writes
        #           to check if the target address is within the memory region 
        #           allocated to the RDT] or by using read-only protection for code pages; 
        #           we use the latter, which is already available in most processors."
        # i.e.:
        explorer.inhibit(graph.find_edge('memacc_write_overwrite', 'ac_code'))

        # comprehensive mem->reg inhibition on the rest
        #   this one does not include malicious_ac_npd
        srcs_to_inhibit = ['ac_reused_fp', 'ac_reused_ra', 'ac_fp', 'ac_ra',
                     'ac_dp', 'conf_cp_in_buffer', 'conf_dp_in_buffer', 'conf_npd_in_buffer']
        srcs_to_inhibit = set([graph.nodes[src] for src in srcs_to_inhibit]) # type: ignore
        for n, incoming_edges in graph.incoming_edges.items():
            for edges in incoming_edges:
                if isinstance(edges, Edge):
                    edges = [edges] # type: ignore
                for edge in edges:
                    if edge.src in srcs_to_inhibit:
                        explorer.inhibit(edge)

        # add malicious_ac_npd manually, because of its double use as payload
        explorer.inhibit(
            graph.find_edge('malicious_ac_npd', 'ac_dcft'),
            graph.find_edge('malicious_ac_npd', 'violate_app_policy'),
            # the rest of em are just used as payload. They are also inhibited,
            #   but the model in the paper does not model these edges; and they are trivially
            #   satisfied by the payload anyway. No security impact here.
        )
    
    @staticmethod
    @citation("kuznetzov2014CPI")
    @prettyname("SafeStack")
    @defense_strategy("IoD")
    @defense_category("CPI")
    @threatmodel([no_forward_edge,rocode])
    def SafeStack(graph: ExploitGraph, explorer : Explorer):
        explorer.inhibit(
            graph.find_edge('memacc_write_overwrite', 'ac_ra'),
            graph.find_edge('memacc_write_subst', 'ac_reused_ra'),
        )

    @classmethod
    @citation("kuznetzov2014CPI")
    @prettyname("CPS")
    @defense_strategy("IoD")
    @defense_category("CPI")
    @threatmodel([rocode])
    def CPS(self, graph: ExploitGraph, explorer : Explorer):
        # SafeStack for RAs
        self.SafeStack(graph, explorer)

        # IoD for FPs
        explorer.inhibit(
            # direct overwrite obviously invalid
            graph.find_edge('memacc_write_overwrite', 'ac_fp'),
            # FP substitutions seem to be allowed in CPS
            # graph.find_edge('memacc_write_subst', 'ac_reused_fp'),

            # crafting is not technically inhibited, I think
            # but it's not possible to forge a code pointer, so we
            #   still inhibit it so that only pre-existing values can be used (subst)
            graph.find_edge('memacc_read_craft', 'ac_fp')

            # read substitution is not inhibited I think
        )

        # i think it's possible to 'trick' practical CPS implementation into reading
        #   from the unsafe region, and craft that way.
        # because forcing unique domain access policy is likely impractical
        # anyway, edge fragility for now. But an interesting option to try in PoC!
 
    @classmethod
    @citation("kuznetzov2014CPI")
    @prettyname("CPI")
    @defense_strategy("IoD")
    @defense_category("CPI")
    @threatmodel([rocode])
    def CPI(self, graph: ExploitGraph, explorer : Explorer):
        self.CPS(graph, explorer)

        # no invalid memory accesses possible on pointers pointing to safe region
        #   i.e. no subst, no read-crafting
        explorer.inhibit(
            graph.find_edge('memacc_write_subst', 'ac_reused_fp'),
            graph.find_edge('memacc_read_subst', 'ac_reused_fp'),
            # just for good measure in case i delete the CPS version
            graph.find_edge('memacc_read_craft', 'ac_fp'),
        )

    # abadi2005CFI is a bad example for CFI: it's not 1 implementation, but many!
    @classmethod
    @citation("llvm-cfi")
    @prettyname("IFCC")
    @defense_strategy("IoU")
    @defense_category("CFI")
    @threatmodel([no_backward_edge,rocode])
    def Clang_IFCC(self, graph: ExploitGraph, explorer : Explorer):
        explorer.inhibit(
            graph.find_edge('ac_fp', 'fg_cfh'),
            graph.find_edge('ac_fp', 'cg_cfh'), # this is very generous
            graph.find_edge('ac_fp', 'ac_pc_data'), # obvs targeting data becomes impossible
            # substition attacks also impossible (generous)
            graph.find_edge('ac_reused_fp', 'cg_cfh')
        )

    @staticmethod
    @citation("intel-cet")
    @prettyname(R"Intel IBT")
    @defense_strategy("IoU")
    @defense_category("CFI")
    @threatmodel([no_backward_edge,rocode])
    def intelIBT(graph: ExploitGraph, explorer : Explorer):
        explorer.inhibit(
            graph.find_edge('ac_fp', 'fg_cfh'),
            graph.find_edge('ac_fp', 'ac_pc_data'),
        )

    @classmethod
    @citation("fineibt")
    @prettyname(R"FineIBT")
    @defense_strategy("IoU")
    @defense_category("CFI")
    @threatmodel([no_backward_edge,rocode])
    def FineIBT(self, graph: ExploitGraph, explorer : Explorer):
        self.intelIBT(graph, explorer)
        explorer.inhibit(
            graph.find_edge('ac_fp', 'fg_cfh'),
            graph.find_edge('ac_fp', 'cg_cfh'),
            graph.find_edge('ac_fp', 'ac_pc_data'),
            graph.find_edge('ac_reused_fp', 'cg_cfh'),
        )

    @staticmethod
    @citation("intel-cet")
    @prettyname(R"Intel Shadow Stack")
    @defense_strategy("IoU")
    @defense_category("CFI")
    @threatmodel([no_forward_edge,rocode])
    def intelSHSTK(graph: ExploitGraph, explorer : Explorer):
        explorer.inhibit(
            graph.find_edge('ac_ra', 'fg_cfh'),
            graph.find_edge('ac_ra', 'ac_pc_data'),
            graph.find_edge('ac_ra', 'cg_cfh'),
            graph.find_edge('ac_reused_ra', 'cg_cfh')
        )

    @classmethod
    @citation("intel-cet")
    @prettyname(R"Intel CET")
    @defense_strategy("IoU")
    @defense_category("CFI")
    @threatmodel([rocode])
    def intelCET(self, graph: ExploitGraph, explorer : Explorer):
        self.intelIBT(graph, explorer)
        self.intelSHSTK(graph, explorer)

    @classmethod
    @citation("zhang2018xomswitch")
    @prettyname("eXec-Only Memory")
    @defense_strategy("IoU")
    @defense_category("XOM")
    def XOM(self, graph: ExploitGraph, explorer: Explorer):
        self.rocode(graph, explorer)
        explorer.inhibit(
            graph.find_edge('memacc_read_leak', 'conf_code_in_buffer'),
        )

    @staticmethod
    @citation("hiser2012ilr")
    @prettyname("ILR")
    @defense_strategy("IoD")
    @defense_category("Code Randomization")
    @threatmodel([DEP])
    def ILR(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.nodes['code_content'],
            graph.nodes['code_location'],
        )

    @classmethod
    @citation("hiser2012ilr,zhang2018xomswitch")
    @prettyname("ILR+XOM")
    @defense_strategy("IoD")
    @defense_category("Code Randomization")
    @threatmodel([DEP])
    def ILR_XOM(self, graph: ExploitGraph, explorer: Explorer):
        self.XOM(graph, explorer)
        self.ILR(graph, explorer)

    @classmethod
    @citation("crane2015itsatrap")
    @prettyname("Readactor++")
    @defense_strategy("IoD")
    @defense_category("Code Randomization")
    @threatmodel([DEP])
    def Readactorpp(self, graph: ExploitGraph, explorer: Explorer):
        # non-readable code
        self.XOM(graph, explorer)
        # randomized code layout (assume fine-grained)
        self.ILR(graph, explorer)
        # code pointer hiding: the leaked CPs give you no info about layout anymore
        #   and _good_ code pointer hiding; that also hides the tables etc.
        explorer.inhibit(
            graph.find_edge('conf_cp_in_buffer', 'leaked_cp'),
        )

    @classmethod
    @citation("n-variant")
    @prettyname("Cox et al. (MVX+ASP)")
    @defense_strategy("IoU")
    @defense_category("MVX")
    def ReMon_coarseDML(self, graph: ExploitGraph, explorer: Explorer):
        self.ReMon_DCL(graph, explorer)
        explorer.inhibit(
            graph.find_edge('conf_dp_in_buffer', 'leaked_dp'),  # triggers divergence
            graph.find_edge('ac_fp', 'ac_pc_data'),
            graph.find_edge('ac_ra', 'ac_pc_data'),
            graph.find_edge('memacc_write_overwrite', 'ac_dp'), # direct pointer overwrites impossible due to replication
            graph.find_edge('memacc_read_craft', 'ac_dp'),      # read crafting also 
        )

    @staticmethod
    @citation("volckaert2016cloning,volckaert2016remon")
    @prettyname("ReMon (MVX+DCL)")
    @defense_strategy("IoU")
    @defense_category("MVX")
    @threatmodel([DEP])
    def ReMon_DCL(graph: ExploitGraph, explorer: Explorer):
        explorer.inhibit(
            graph.nodes['code_location'],
            graph.find_edge('conf_cp_in_buffer', 'leaked_cp'),  # triggers divergence
            graph.find_edge('ac_fp', 'fg_cfh'),
            graph.find_edge('ac_fp', 'cg_cfh'),
            graph.find_edge('ac_ra', 'fg_cfh'),
            graph.find_edge('ac_ra', 'cg_cfh'),
        )

    @classmethod
    @citation("koning2016mvarmor")
    @prettyname("MvArmor (MVX+ASP-DLK)")
    @defense_strategy("IoD, IoU")
    @defense_category("MVX")
    def ReMon_fineDML(self, graph: ExploitGraph, explorer: Explorer):
        self.ReMon_coarseDML(graph, explorer)
        explorer.inhibit(
            graph.nodes['data_location'],
            graph.find_edge('conf_npd_in_buffer', 'leaked_npd'),            # triggers divergence
            graph.find_edge('conf_dp_in_buffer', 'leaked_dp'),              # triggers divergence
            graph.find_edge('conf_code_in_buffer', 'leaked_code'),          # triggers divergence
            graph.find_edge('conf_cp_in_buffer', 'leaked_cp'),              # triggers divergence
        )

    @classmethod
    @citation("kenali")
    @prettyname(R"\textsc{Kenali}")
    @defense_strategy("IoD")
    @defense_category("Sensitive Data Integrity")
    @threatmodel([no_control_data,rocode])
    def KENALI(self, graph: ExploitGraph, explorer: Explorer):
        # like CPI but for "security-critical conditions"
        explorer.inhibit(
            graph.find_edge('memacc_write_overwrite', 'malicious_ac_npd'),
            graph.find_edge('memacc_write_subst', 'malicious_ac_npd'),
            
            graph.find_edge('memacc_read_craft', 'malicious_ac_npd'),
            graph.find_edge('memacc_read_subst', 'malicious_ac_npd'),
        )

    @classmethod
    @citation("geden2020truvin")
    @prettyname(R"\textsc{TRUVIN}")
    @defense_strategy("IoU")
    @defense_category("Sensitive Data Integrity")
    @threatmodel([no_control_data,rocode])
    def TRUVIN(self, graph: ExploitGraph, explorer: Explorer):
        # basically VIP for conditional inhibition of DOP attacks
        #   == CPI "in debug mode"
        explorer.inhibit(
            graph.find_edge('malicious_ac_npd', 'ac_dcft'),
            graph.find_edge('malicious_ac_npd', 'violate_app_policy'),
            # the rest of em are just used as payload. They are also inhibited,
            #   but the model in the paper does not model these edges; 
            #   wherever they are useful is out of scope anyway
        )


    """
    ********** More Mapped Defenses **********
    The below defenses should appear in Appended table to the paper
    """

    # *** Baggy Bounds Checking (USENIX Security 2009) ***
    # Link: https://www.usenix.org/legacy/event/sec09/tech/full_papers/akritidis.pdf
    @staticmethod
    @citation("baggybounds")
    @prettyname("Baggy Bounds")
    @defense_strategy("MS")
    @defense_category("Spatial")
    @threatmodel([no_uninit,no_miscasts,no_temporal])
    def BaggyBounds(graph: ExploitGraph, explorer: Explorer):
        # Object-based spatial safety
        # Baggy enforces allocation bounds (coarse-grained), so it may have edge-fragility
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_oob'),
        )

    # Optional design instance from the same paper: using upper bits on 64-bit platforms to encode size info.
    # Design-level policy is identical in this graph model; this is just a separate “instance” label.
    @classmethod
    @citation("baggybounds")
    @prettyname("Baggy Bounds (64-bit)")
    @defense_strategy("MS")
    @defense_category("Spatial")
    @threatmodel([no_uninit,no_miscasts,no_temporal])
    def BaggyBounds_64bit(self, graph: ExploitGraph, explorer: Explorer):
        self.BaggyBounds(graph, explorer)

    # *** PTAuth: Temporal Memory Safety via Robust Points-to Authentication (USENIX Security 2021) ***
    # Link: https://www.usenix.org/conference/usenixsecurity21/presentation/mirzazade
    # Basically Lock&Key: Key is PAC, Lock is tweak allocated before start of obj
    @staticmethod
    @citation("ptauth")
    @prettyname("PTAuth")
    @defense_strategy("MS")
    @defense_category("Temporal")
    @threatmodel([no_spatial, no_miscasts, no_uninit])
    def PTAuth(graph: ExploitGraph, explorer: Explorer):
        # stop temporal violations at dereference time depending on Pointer Authentication
        explorer.inhibit(
            graph.find_edge('dp_to_dangling', 'memacc_read'),
            graph.find_edge('dp_to_dangling', 'memacc_write'),
        )

    # OTA per execution unit -> deterministic quarantaining (without needing to track; static evidence)
    @staticmethod
    @citation("yagemann2023pumm")
    @prettyname("PUMM")
    @defense_strategy("MS")
    @defense_category("Temporal")
    @threatmodel([no_spatial,no_miscasts,no_uninit])
    def PUMM(graph: ExploitGraph, explorer: Explorer):
        # objects are never really "free", until all dangling pointers are no longer used
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_free'),
        )


    # *** CAMP: Compiler and Allocator-based Heap Memory Protection (USENIX Security 2024) ***
    # Link: https://www.usenix.org/system/files/usenixsecurity24-lin-zhenpeng.pdf 
    @staticmethod
    @citation("camp")
    @prettyname("CAMP")
    @defense_strategy("MS")
    @defense_category("Spatial, Temporal")
    @threatmodel([no_uninit,no_miscasts])
    def CAMP(graph: ExploitGraph, explorer: Explorer):
        # Focus is only on heap (edge fragile): our model considers it for full protection
        # Spatial heap protection is object-based (ptr arithmetic)
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_oob'),
        )
        # Temporal heap protection: neutralizes dangling pointers
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_free')
        )
        # I'm not sure if also CAMP can be mapped as UAF prevention by "no reuse" policy, and thus the mapping could look like:
        # explorer.inhibit(
        #    graph.find_edge('alloc', 'dp_to_dangling'),
        #)
        # Their description is a bit unclear. So, we did not consider this stronger defense version


    # *** ShadowBound: Efficient Heap Memory Protection Through Advanced Metadata Management and Customized Compiler Optimization (USENIX Security 2024) ***
    # Link: https://www.usenix.org/system/files/usenixsecurity24-yu-zheng.pdf 
    @staticmethod
    @citation("shadowbound")
    @prettyname("ShadowBound")
    @defense_strategy("MS")
    @defense_category("Spatial")
    @threatmodel([no_uninit,no_miscasts,no_temporal])
    def ShadowBound(graph: ExploitGraph, explorer: Explorer):
        """
        Core ShadowBound provides only object-based spatial protection.
        Focus is only on heap --> potential edge fragility
        """
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_oob'),
        )

    # The authors also show a teaming up of Shadowbound with UAF defenses, e.g., MarkUs, FFMalloc, PUMM
    @classmethod
    @citation("shadowbound")
    @prettyname("ShadowBound-MarkUs")
    @defense_strategy("MS")
    @defense_category("Spatial, Temporal")
    @threatmodel([no_uninit,no_miscasts])
    def ShadowBound_MarkUs(self, graph: ExploitGraph, explorer: Explorer):
        self.ShadowBound(graph, explorer)
        self.MarkUs(graph, explorer)

    @classmethod
    @citation("shadowbound")
    @prettyname("ShadowBound-FFMalloc")
    @defense_strategy("MS")
    @defense_category("Spatial, Temporal")
    @threatmodel([no_uninit,no_miscasts])
    def ShadowBound_FFMalloc(self, graph: ExploitGraph, explorer: Explorer):
        self.ShadowBound(graph, explorer)
        self.FFMalloc(graph, explorer)

    @classmethod
    @citation("shadowbound")
    @prettyname("ShadowBound-PUMM")
    @defense_strategy("MS")
    @defense_category("Spatial, Temporal")
    @threatmodel([no_uninit,no_miscasts])
    def ShadowBound_PUMM(self, graph: ExploitGraph, explorer: Explorer):
        self.ShadowBound(graph, explorer)
        self.PUMM(graph, explorer)

    # *** DANGNULL: Preventing Use-after-free with Dangling Pointers Nullification (NDSS 2015) ***
    # Link: https://wenke.gtisc.gatech.edu/papers/dangnull.pdf
    @staticmethod
    @citation("lee2015dangnull")
    @prettyname("DANGNULL")
    @defense_strategy("MS")
    @defense_category("Temporal")
    @threatmodel([no_spatial,no_miscasts,no_uninit])
    def DANGNULL(graph: ExploitGraph, explorer: Explorer):
        # DANGNULL prevents use-after-free by nullifying all pointers to an object when it is freed.
        #   Hence, no pointers to free memory can exist
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_free'),
        )

    # *** Oscar: A Practical Page-Permissions-Based Scheme for Thwarting Dangling Pointers (USENIX Security 2017) ***
    # Link: https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-dang.pdf
    # No threat model!
    @staticmethod
    @citation("oscar")
    @prettyname("Oscar")
    @defense_strategy("MS")
    @defense_category("Temporal")
    @threatmodel([no_spatial,no_uninit,no_miscasts])
    def Oscar(graph: ExploitGraph, explorer: Explorer):
        # Oscar aims to never reuse the same VA -> no reused addresses
        # All dangling pointers are invalidated by making their unique VA inaccessible using page permissions
        #   -> caught at dereference
        explorer.inhibit(
            graph.find_edge('dp_to_dangling', 'memacc_read'),
            graph.find_edge('dp_to_dangling', 'memacc_write'),
        )

    # *** Type Casting Verification: Stopping an Emerging Attack Vector (USENIX Security 2015) ***
    # Link: https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-lee.pdf
    @staticmethod
    @citation("typecastingverification")
    @prettyname("CAVER")
    @defense_strategy("MS")
    @defense_category("Miscasts")
    @threatmodel([no_spatial,no_uninit,no_temporal])
    def CAVER(graph: ExploitGraph, explorer: Explorer):
        # CAVER performs runtime type cast verification to detect bad-casting.
        # In our exploit graph, bad-casting corresponds to invalid type-confused pointer capabilities that lead to memory corruption
        # when dereferenced. We thus inhibit that edge.
        explorer.inhibit(
            graph.find_edge("v_dp_reg", "dp_to_type_confused"),
        )


    # *** Type++: Prohibiting Type Confusion With Inline Type Information (NDSS 2025) ***
    # Link: https://www.ndss-symposium.org/wp-content/uploads/2025-53-paper.pdf
    @staticmethod
    @citation("type++")
    @prettyname("Type++")
    @defense_strategy("MS")
    @defense_category("Miscasts")
    @threatmodel([no_uninit,no_spatial,no_temporal])
    def TypePP(graph: ExploitGraph, explorer: Explorer):
        """
        Type++ prevents (downcasting) type confusion by enforcing type checks on casts.
        This can be represented as preventing the creation of a type-confused pointer capability.
        """
        explorer.inhibit(
            graph.find_edge('v_dp_reg', 'dp_to_type_confused'),
        )

    # *** Timely Rerandomization for Mitigating Memory Disclosures (CCS 2015) ***
    # Link: https://web.mit.edu/ha22286/www/papers/CCS15_2.pdf
    @classmethod
    @citation("bigelow2015timely")
    @prettyname("TASR")
    @defense_strategy("IoD")
    @defense_category("Code/Data Randomization")
    @threatmodel([rocode,DEP])
    def TASR(self, graph: ExploitGraph, explorer: Explorer):
        # Rerandomize the layout of code on every output syscall -> if the attacker leaked, it is now invalid
        # This means that leaked code pointers no longer lead to CLK now
        explorer.inhibit(
            graph.find_edge('leaked_cp', 'code_location'),
        )
        self.codeASLR(graph, explorer)

    # *** VIP: Safeguard Value Invariant Property for Thwarting Critical Memory Corruption Attacks (CCS 2021) ***
    # Link: https://dl.acm.org/doi/10.1145/3460120.3485376
    # This paper has 4 variants of defenses
    @staticmethod
    @citation("vip")
    @prettyname("VIP-CFI")
    @defense_strategy("IoU")
    @defense_category("CFI")
    @threatmodel([rocode,DEP,SafeStack])
    def VIP_CFI(graph: ExploitGraph, explorer: Explorer):
        """
        VIP-CFI: uses HyperSpace to store valid copies of FE code pointers. Validates them on memory reads.
        It's CPS protection, but with Integrity of Use (IoU) checks rather than Isolation of Data (IoD)
        """
        # can't read corrupted FPs into registers
        explorer.inihibit_all_edges_from('ac_fp')

    @classmethod
    @citation("vip")
    @prettyname("VIP-CPI")
    @defense_strategy("IoD, IoU")
    @defense_category("CPI")
    @threatmodel([rocode,DEP,SafeStack])
    def VIP_CPI(self, graph: ExploitGraph, explorer: Explorer):
        """
        Same as VIP-CFI, but also includes data pointers to function pointers (recursively).
        This means it implements Kuznetsov et al.'s "CPI" (instead of CPS cfr. VIP-CFI), 
        BUT still with Integrity of Use checks rather than Isolation of Data
        """
        self.VIP_CFI(graph, explorer)
        # now, also protect overwrites of data pointers. 
        # The paper technically only protects data pointers that (recursively) point to function pointers
        #   but we can't model such selectivity, so we will protect _all_ data pointers instead
        #   still IoU on them though: basically only read crafting DPs is impossible
        explorer.inhibit(
            graph.find_edge('memacc_read_craft', 'ac_dp')
        )



    # *** ARM BTI (in AArch8.5v and later). Clang option: -mbranch-protection=bti ***
    # Link: https://developer.arm.com/documentation/ddi0602/2021-12/Base-Instructions/BTI--Branch-Target-Identification-
    @staticmethod
    @citation("arm-bti")
    @prettyname("ARM BTI")
    @defense_strategy("IoU")
    @defense_category("CFI")
    @threatmodel([no_backward_edge,rocode,DEP])
    def ARM_BTI(graph: ExploitGraph, explorer : Explorer):
        # ARM BTI is the equivalent to Intel IBT
        explorer.inhibit(
            graph.find_edge('ac_fp', 'fg_cfh'),
            graph.find_edge('ac_fp', 'ac_pc_data'),
        )


    # *** ARM PAC-RET (in AArch8.3v and later). Clang option: -mbranch-protection=pac-ret ***
    # Link: https://gcc.gnu.org/legacy-ml/gcc-patches/2018-11/msg00104.html
    @staticmethod
    @citation("pac-ret")
    @prettyname("PAC-RET")
    @defense_strategy("IoU")
    @defense_category("CFI")
    @threatmodel([no_forward_edge,rocode,DEP])
    def PAC_RET(graph: ExploitGraph, explorer : Explorer):
        # PAC-RET is really complex to map as preventing attackers from obtainting certain capabilities is implementation dependent.
        # Below is a mapping of the strongest protection of PAC-RET
        explorer.inhibit(
            # prevent adversaries from obtaining a corrupted return-address capability
            graph.find_edge('memacc_write_overwrite', 'ac_ra'),
            # prevent substitution/replay of a previously valid return address
            graph.find_edge('memacc_write_subst', 'ac_reused_ra'),
            # prevent backward-edge hijack outcomes; This is equivalent to a shadow stack!
            graph.find_edge('ac_ra', 'fg_cfh'),
            graph.find_edge('ac_ra', 'ac_pc_data'),
            graph.find_edge('ac_ra', 'cg_cfh'),
            graph.find_edge('ac_reused_ra', 'cg_cfh')
        )


    # *** ARM (AArch64) standard protection:PAC-RET + BTI. Clang option: -mbranch-protection=standard ***
    @classmethod
    @citation("arm-bti,pac-ret")
    @prettyname("Clang Standard Protection (ARM)")
    @defense_strategy("IoU")
    @defense_category("CFI")
    @threatmodel([rocode,DEP])
    def Clang_Standard_Protection_ARM(self, graph: ExploitGraph, explorer : Explorer):
        # ARM standard protection = PAC-RET + BTI
        self.ARM_BTI(graph, explorer)
        self.PAC_RET(graph, explorer)


    # *** CFA+ (USENIX Security 2024) ***
    # Link: https://www.usenix.org/conference/usenixsecurity24/presentation/ammar
    @classmethod
    @citation("cfa+")
    @prettyname("CFA+")
    @defense_strategy("IoU, PED")
    @defense_category("CFI")
    @threatmodel([rocode,DEP])
    def CFAplus(self, graph: ExploitGraph, explorer: Explorer):
        """
        Map CFA+ as (i) BTI landing-pad enforcement + (ii) indirect-call
        legitimacy checking + (iii) return-address masking/unmasking.
        - This blocks both function- and instruction-granular CF hijacks:
            - Prevents instruction-granular CF hijacks via indirect branches (incl. ret)
            - Prevents direct jumps to injected data via indirect branches in the model
            - Does NOT prevent function-granular control-flow reuse (WFR-style)
        - Note: Post-exploit detection is not shown here; it should in principle detect (not prevent!) WFR-style exploits.
        """
        # Map ARM BTI first; Forward-edge protection from corrupted function pointers
        self.ARM_BTI(graph, explorer)
        explorer.inhibit(
            # SW instrumentation in CFA+ makes BTI finer grained; This part is equivalent to FineIBT.
            graph.find_edge('ac_fp', 'cg_cfh'),
            graph.find_edge('ac_reused_fp', 'cg_cfh'),
            # backward-edge (via corrupted return addresses) — BTI applies to `ret` too
            graph.find_edge('ac_ra', 'fg_cfh'),
            graph.find_edge('ac_ra', 'ac_pc_data'),
            graph.find_edge('ac_ra', 'cg_cfh'),
            graph.find_edge('ac_reused_ra', 'cg_cfh'),
        )

    """
    ********** End of Mapped Defenses **********
    """


# Get methods in declaration order
def get_defense_methods():
    methods = list[tuple[str,Callable[[ExploitGraph,Explorer],None]]]()
    for name, method in Defenses.__dict__.items():
        func = getattr(Defenses, name)
        if callable(func) and hasattr(func, 'citation'):
            methods.append((name, func))
    return methods
    
def run_fragility_test(defenses, graph = None, prefix="",  include_threat_model: bool = False, print_results = True):
    if not graph:
        graph = ExploitGraph()
    explorer = Explorer(graph)

    def apply_defense(defense):
        defense(graph, explorer)
        if include_threat_model and hasattr(defense, 'threatmodel'):
            for d in getattr(defense, 'threatmodel'):
                apply_defense(d)

    for name in defenses:
        func = getattr(Defenses, name)
        apply_defense(func)

    def myprint(str):
        if print_results:
            print(str)
        
    myprint(f"{prefix}initial nodes: {explorer.initial_reached_nodes}")
    for case in explorer.enumerate_predicate_combinations():
        myprint(f"{prefix}for case: {case}:")
        reached_nodes = explorer.get_reached_nodes()
        myprint(f"\treached goals: {[n for n in reached_nodes if n.type == 'goal']}")
        myprint(f"\tnon-reached goals: {[n for n in graph.nodes.values() if n not in reached_nodes and n.type == 'goal']}")
        if print_results:
            export_to_file(graph, f'{prefix}defense', explorer, highlight_defendable=False)

    return explorer

class InteropResult:
    def __init__(self, defense, explorer, original_self_goals, original_merged_goals, new_self_goals):
        self.defense = defense
        self.explorer = explorer
        self.original_self_goals = original_self_goals.copy()
        self.original_merged_goals = original_merged_goals.copy()
        self.new_self_goals = new_self_goals.copy()

    def was_bypassed(self) -> Optional[list[Node]]:
        unlocked_goals = []
        for goal in self.new_self_goals:
            if goal not in self.original_self_goals:
                unlocked_goals.append(goal)
        if len(unlocked_goals) == 0:
            return None
        return unlocked_goals
    
    def unlocked_completely_new_goals(self) -> Optional[list[Node]]:
        unlocked_goals = []
        for goal in self.new_self_goals:
            if goal not in self.original_merged_goals:
                unlocked_goals.append(goal)
        if len(unlocked_goals) == 0:
            return None
        return unlocked_goals

def run_interop_test(defenses1: list[str], defenses2: list[str], print_results = True) -> tuple[InteropResult,InteropResult]:
    graph = ExploitGraph()
    total_reached = set[Node]()
    explorer1 = run_fragility_test(defenses1, graph, f"set 1 ({defenses1}): ", print_results=print_results)
    old_explorer1_goals = [n for n in explorer1.get_reached_nodes() if n.type == "goal"]
    total_reached.update(explorer1.get_reached_nodes())
    explorer2 = run_fragility_test(defenses2, graph, f"set 2: ({defenses2}): ",  print_results=print_results)
    old_explorer2_goals = [n for n in explorer2.get_reached_nodes() if n.type == "goal"]
    total_reached.update(explorer2.get_reached_nodes())

    # now figure out whether they combine well, or whether there is impedance mismatch

    explorer1.update_initial_nodes(total_reached)
    explorer2.update_initial_nodes(total_reached)

    return InteropResult(defenses1, explorer1, old_explorer1_goals, total_reached, [n for n in explorer1.get_reached_nodes() if n.type == "goal"]), InteropResult(defenses2, explorer2, old_explorer2_goals, total_reached, [n for n in explorer2.get_reached_nodes() if n.type == "goal"])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Fragility analysis tool")
    subparsers = parser.add_subparsers(dest='command')

    parser_frag = subparsers.add_parser('fragility', help='Run fragility test')
    parser_frag.add_argument(
        'defenses', nargs='+', help='List of defenses'
    )
    parser_frag.add_argument(
        '--include-threat-model', action='store_true', help="Also inhibit everything from the threat model"
    )

    parser_interop = subparsers.add_parser('interop', help='Run interoperability test')
    parser_interop.add_argument(
        '--set1', nargs='+', required=True, help='First set of defenses'
    )
    parser_interop.add_argument(
        '--set2', nargs='+', required=True, help='Second set of defenses'
    )

    args = parser.parse_args()

    if args.command == 'fragility':
        run_fragility_test(args.defenses, include_threat_model=args.include_threat_model)
    elif args.command == 'interop':
        for result in run_interop_test(args.set1, args.set2):
            if new_goals := result.was_bypassed():
                print(f"\n{result.defense} got interop-bypassed! Goals {new_goals} are now possible")
                if (completely_new_goals := result.unlocked_completely_new_goals()):
                    print(f"\t it now even allows completely new goals: {completely_new_goals}")
                export_to_file(result.explorer._graph, f'bypassed-defense-2', result.explorer, highlight_defendable=False)
    else:
        parser.print_help()
