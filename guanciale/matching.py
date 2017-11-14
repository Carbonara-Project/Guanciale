#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, willownoises@gmail.com"

import pyvex
import archinfo
import hashlib

r2_arch_map = {
    ("arm", 64): archinfo.ArchAArch64,
    ("arm", 32): archinfo.ArchARM,
    ("x86", 64): archinfo.ArchAMD64,
    ("avr", 16): archinfo.ArchAVR,
    ("mips", 32): archinfo.ArchMIPS32,
    ("mips", 64): archinfo.ArchMIPS64,
    ("ppc", 32): archinfo.ArchPPC32,
    ("ppc", 64): archinfo.ArchPPC64,
    ("x86", 32): archinfo.ArchX86
}


ida_arch_map = {
    ("arm", 64): archinfo.ArchAArch64,
    ("armb", 64): archinfo.ArchAArch64,
    ("arm", 32): archinfo.ArchARM,
    ("armb", 32): archinfo.ArchARM,
    ("metapc", 64): archinfo.ArchAMD64,
    ("avr", 16): archinfo.ArchAVR, #??? check if it is true in ida
    ("mips", 32): archinfo.ArchMIPS32,
    ("mipsb", 32): archinfo.ArchMIPS32,
    ("mips64", 64): archinfo.ArchMIPS64,
    ("mips64b", 64): archinfo.ArchMIPS64,
    ("ppc", 32): archinfo.ArchPPC32,
    ("ppcb", 32): archinfo.ArchPPC32,
    ("ppc64", 64): archinfo.ArchPPC64,
    ("ppc64b", 64): archinfo.ArchPPC64,
    ("metapc", 32): archinfo.ArchX86
    #TODO add more ida processors in the map
}

def archFromR2(arch, bits, endian):
    a = r2_arch_map[(arch, bits)]
    if endian != "little":
        return a(archinfo.Endness.BE)
    return a(archinfo.Endness.LE)

def archFromIda(processor, bits, endian):
    a = ida_arch_map[(processor, bits)]
    if endian != "little":
        return a(archinfo.Endness.BE)
    return a(archinfo.Endness.LE)


class JumpInsn(object):
    def __init__(self, offset, size, addr, jumpout=False):
        self.offset = offset
        self.size = size
        self.addr = addr
        self.jumpout = jumpout
    
    def __str__(self):
        return "JumpInsn(off:%x, siz:%d, tgt:%x, out:%r)" % (self.offset, self.size, self.addr, self.jumpout)

class CallInsn(JumpInsn):
    def __init__(self, offset, size, addr, fcn_name, is_api=False):
        JumpInsn.__init__(self, offset, size, addr, True)
        self.fcn_name = fcn_name
        self.is_api = is_api

    def __str__(self):
        return "CallInsn(off:%x, siz:%d, tgt:%x, name:%s, api:%r)" % (self.offset, self.size, self.addr, self.fcn_name, self.is_api)

class ProcedureHandler(object):
    def __init__(self, code, insns_list, offset, bb_insns, arch):
        self.insns_list = insns_list
        self.offset = offset
        self.bb_insns = bb_insns
        self.arch = arch
        self.code = code
        self.size = len(code)


    def liftByBlocks(self):
        bb = [0]
        for instr in self.bb_insns:
            if instr.jumpout:
                #if jump out continue with the next instruction
                next = instr.offset + instr.size - self.offset
                if next < self.size and next not in bb:
                    bb.append(next)
            else:
                if instr.addr - self.offset not in bb:
                    bb.append(instr.addr - self.offset)
                next = instr.offset + instr.size - self.offset
                if next < self.size and next not in bb:
                    bb.append(next)

        bb.sort()
        bb.append(self.offset + self.size)
        consts = {}
        ips = []
        vex_code = ""
        
        pc_offset = self.arch.registers["pc"][0]
        regs = {}
        irsbs = []

        for bidx in xrange(len(bb) -1):
            irsb = pyvex.IRSB(self.code[bb[bidx]:bb[bidx+1]], self.offset + bb[bidx], self.arch, opt_level=0)
            irsbs.append(irsb)
        
            stmts = irsb.statements
            
            for i in xrange(len(stmts)):
                #TODO PutI GetI
                
                if isinstance(stmts[i], pyvex.stmt.Put):
                    if stmts[i].offset == pc_offset and len(stmts[i].constants) == 1: 
                        ips.append(stmts[i].constants[0].value)
                        stmts[i].reg_name = "<>"
                    else:
                        # constants abstraction
                        for c in stmts[i].constants:
                            consts[c.value] = consts.get(c.value, len(consts))
                            c.value = consts[c.value]
                        
                    # registers abstraction
                    regs[stmts[i].offset] = regs.get(stmts[i].offset, len(regs))
                    stmts[i].offset = regs[stmts[i].offset]
                elif isinstance(stmts[i], pyvex.stmt.Exit):
                    ips.append(stmts[i].dst.value)
                    # registers abstraction
                    regs[stmts[i].offsIP] = regs.get(stmts[i].offsIP, len(regs))
                    stmts[i].offsIP = regs[stmts[i].offsIP]
                else:
                    # constants abstraction
                    for c in stmts[i].constants:
                        consts[c.value] = consts.get(c.value, len(consts))
                        c.value = consts[c.value]
                for expr in stmts[i].expressions:
                    if isinstance(expr, pyvex.expr.Get):
                        # registers abstraction
                        regs[expr.offset] = regs.get(expr.offset, len(regs))
                        expr.offset = regs[expr.offset]

        #order addresses
        addrs = {}
        ips.sort()
        for i in xrange(len(ips)):
            addrs[ips[i]] = i
        
        for irsb in irsbs:
            stmts = irsb.statements
                     
            for i in xrange(len(stmts)):
                if isinstance(stmts[i], pyvex.stmt.IMark) or isinstance(stmts[i], pyvex.stmt.AbiHint):
                    continue
                
                if hasattr(stmts[i], "reg_name") and stmts[i].reg_name == "<>":
                    stmts[i].constants[0].value = addrs[stmts[i].constants[0].value]
                elif isinstance(stmts[i], pyvex.stmt.Exit):
                    stmts[i].dst.value = addrs[stmts[i].dst.value]
                
                vex_code += stmts[i].__str__() + "\n"
        
        self.consts = consts
        self.ips = ips
        self.vex_code = vex_code
        
        consts_list = sorted(consts, key=consts.get)
        
        self.consts_hash = hashlib.md5(str(consts_list)).digest()
        self.vex_code_hash = hashlib.md5(vex_code).digest()
        
        '''
        import json
        print "----- ProcedureHandler.lift() -----"
        print vex_code
        print
        print "REGS: " + json.dumps(regs, indent=2)
        print "CONSTS: " + json.dumps(consts, indent=2)
        print "IPS: " + json.dumps(ips, indent=2)
        print "-----------------------------------"
        '''


    def liftByInsns(self):
        consts = {}
        ips = []
        vex_code = ""
        
        pc_offset = self.arch.registers["pc"][0]
        regs = {}
        irsbs = []

        
        for instr in self.insns_list:
            irsb = pyvex.IRSB(instr, 0, self.arch, opt_level=0)
            irsbs.append(irsb)
        
            stmts = irsb.statements
            
            for i in xrange(len(stmts)):
                #TODO PutI GetI
                
                if isinstance(stmts[i], pyvex.stmt.Put):
                    if stmts[i].offset == pc_offset and len(stmts[i].constants) == 1: 
                        ips.append(stmts[i].constants[0].value)
                        stmts[i].reg_name = "<>"
                    else:
                        # constants abstraction
                        for c in stmts[i].constants:
                            consts[c.value] = consts.get(c.value, len(consts))
                            c.value = consts[c.value]
                        
                    # registers abstraction
                    regs[stmts[i].offset] = regs.get(stmts[i].offset, len(regs))
                    stmts[i].offset = regs[stmts[i].offset]
                elif isinstance(stmts[i], pyvex.stmt.Exit):
                    ips.append(stmts[i].dst.value)
                    # registers abstraction
                    regs[stmts[i].offsIP] = regs.get(stmts[i].offsIP, len(regs))
                    stmts[i].offsIP = regs[stmts[i].offsIP]
                else:
                    # constants abstraction
                    for c in stmts[i].constants:
                        consts[c.value] = consts.get(c.value, len(consts))
                        c.value = consts[c.value]
                for expr in stmts[i].expressions:
                    if isinstance(expr, pyvex.expr.Get):
                        # registers abstraction
                        regs[expr.offset] = regs.get(expr.offset, len(regs))
                        expr.offset = regs[expr.offset]

        #order addresses
        addrs = {}
        ips.sort()
        for i in xrange(len(ips)):
            addrs[ips[i]] = i
        
        for irsb in irsbs:
            stmts = irsb.statements
                     
            for i in xrange(len(stmts)):
                if isinstance(stmts[i], pyvex.stmt.IMark) or isinstance(stmts[i], pyvex.stmt.AbiHint):
                    continue
                
                if hasattr(stmts[i], "reg_name") and stmts[i].reg_name == "<>":
                    stmts[i].constants[0].value = addrs[stmts[i].constants[0].value]
                elif isinstance(stmts[i], pyvex.stmt.Exit):
                    stmts[i].dst.value = addrs[stmts[i].dst.value]
                
                vex_code += stmts[i].__str__() + "\n"
        
        self.consts = consts
        self.ips = ips
        self.vex_code = vex_code
        
        consts_list = sorted(consts, key=consts.get)
        
        self.consts_hash = hashlib.md5(str(consts_list)).digest()
        self.vex_code_hash = hashlib.md5(vex_code).digest()
        
        '''
        import json
        print "----- ProcedureHandler.lift() -----"
        print vex_code
        print
        print "REGS: " + json.dumps(regs, indent=2)
        print "CONSTS: " + json.dumps(consts, indent=2)
        print "IPS: " + json.dumps(ips, indent=2)
        print "-----------------------------------"
        '''

    def lift(self):
        try:
            self.liftByBlocks()
        except pyvex.errors.PyVEXError as err:
            #print err
            self.liftByInsns()       


    def handleFlow(self):
        
        #TODO replace sorting loops with sorted function
        api = []
        internals = []
        jumps = []
        api_str = ""

        for instr in self.bb_insns:
            if isinstance(instr, CallInsn):
                if instr.is_api:
                    api_str += str(instr.fcn_name) + ","
                    api.append(instr.fcn_name)
                else:
                    internals.append(instr.addr)
            else:
                if not instr.jumpout:
                    jumps.append(instr.addr)
        
        self.api_hash = hashlib.md5(api_str).digest()
        
        jumps.sort()
        jumps_dict = {}
        for i in xrange(len(jumps)):
            jumps_dict[jumps[i]] = i
        
        sorted = internals[:]
        sorted.sort()
        calleds_dict = {}
        for i in xrange(len(sorted)):
            calleds_dict[sorted[i]] = i
        for i in xrange(len(internals)):
            internals[i] = calleds_dict[internals[i]]
        
        self.jumps_flow = []
        self.flow = []
        jumps_flow_str = ""
        flow_str = ""
        
        for instr in self.bb_insns:
            if isinstance(instr, CallInsn):
                if instr.is_api:
                    self.flow.append(instr.fcn_name)
                    flow_str += "@" + instr.fcn_name + ","
            else:
                if not instr.jumpout:
                    self.flow.append(jumps_dict[instr.addr])
                    self.jumps_flow.append(jumps_dict[instr.addr])
                    jumps_flow_str += str(jumps_dict[instr.addr]) + ","
                    flow_str += str(jumps_dict[instr.addr]) + ","
        
        internals_str = ""
        for fn in internals:
            internals_str += str(fn) + ","
        
        self.internals_hash = hashlib.md5(internals_str).digest()
        self.jumps_flow_hash = hashlib.md5(jumps_flow_str).digest()
        self.flow_hash = hashlib.md5(flow_str).digest()
        self.api = api
        
        '''
        import json
        print "----- ProcedureHandler.handleFlow() -----"
        print "API: " + json.dumps(self.api, indent=2)
        print "INTERNALS: " + json.dumps(internals, indent=2)
        print "JUMPS FLOW: " + json.dumps(self.jumps_flow, indent=2)
        print "FLOW: " + json.dumps(self.flow, indent=2)
        print "-----------------------------------"
        '''




        

