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

''' HOW TO GET ARCH IN IDAPYTHON?
import idaapi

info = idaapi.get_inf_structure()

if info.is_64bit():
    bits = 64
elif info.is_32bit():
    bits = 32
else:
    bits = 16

endian = "little"
if info.mf:
    endian = "big"
'''

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
    a = ida_arch_map[(arch, bits)]
    if endian != "little":
        return a(archinfo.Endness.BE)
    return a(archinfo.Endness.LE)



class CallInsn(object):
    def __init__(self, offset, size, fcn_addr, fcn_name, is_api=False):
        self.offset = offset
        self.size = size
        self.fcn_addr = fcn_addr
        self.fcn_name = fcn_name
        self.is_api = is_api

class JumpInsn(object):
    def __init__(self, offset, size, addr, jumpout=False):
        self.offset = offset
        self.size = size
        self.addr = addr
        self.jumpout = jumpout


class AbstractProcedure(object):
    def __init__(code, offset, calls_insns, jumps_insns, arch):
        self.code = code
        self.offset = offset
        self.endaddr = offset + len(code)
        self.calls_insns = calls_insns
        self.jumps_insns = jumps_insns
        self.arch = arch
    
    def lift_helper(self, irsb):
        stmts = irsb.statements
        
        for i in xrange(len(stmts)):
            #TODO PutI GetI Exit
            
            # registers abstraction
            if isinstance(stmts[i], pyvex.stmt.Put):
                regs[stmts[i].offset] = regs.get(stmts[i].offset, len(regs))
                stmts[i].offset = regs[stmts[i].offset]
                
                if i+1 < len(stmts) and isinstance(stmts[i+1], pyvex.stmt.IMark) and len(stmts[i].constants) == 1: #problably program counter? self.arch["pc"]
                    ips.append(stmts[i].constants[0].value)
                else:
                    # constants abstraction
                    for c in stmts[i].constants:
                        consts[c.value] = consts.get(c.value, len(consts))
                        c.value = consts[c.value]
            else:
                # constants abstraction
                for c in stmts[i].constants:
                    consts[c.value] = consts.get(c.value, len(consts))
                    c.value = consts[c.value]
            for expr in stmts[i].expressions:
                if isinstance(expr, pyvex.expr.Get):
                    regs[expr.offset] = regs.get(expr.offset, len(regs))
                    expr.offset = regs[expr.offset]
            
        for i in xrange(len(stmts)):
            if isinstance(stmts[i], pyvex.stmt.IMark) or isinstance(stmts[i], pyvex.stmt.AbiHint):
                continue
            
            if isinstance(stmts[i], pyvex.stmt.Put) and  i+1 < len(stmts) and isinstance(stmts[i+1], pyvex.stmt.IMark) and len(stmts[i].constants) == 1:
                stmts[i].constants[0].value = addrs[stmts[i].constants[0].value]
            
        vex_code += stmts[i].__str__() + "\n"
        
        for tgt in irsb.constant_jump_targets:
            
            if tgt < self.offset and tgt >= self.endaddr:
                continue
            if tgt in self.bb: # skip loops
                continue
            nirsb = pyvex.IRSB(self.code[tgt - self.offset:], tgt, self.arch)
            self.lift_helper(nirsb)
    
    def lift(self):
        self.consts = {}
        self.regs = {}
        self.ips = []
        self.bb = [self.code]
        self.vex_code = ""
        
        irsb = pyvex.IRSB(self.code, self.offset, self.arch)
        self.lift_helper(irsb)



def handleCalledFunctions(calleds): #side-effect!
    sorted = calleds[:]
    sorted.sort()
    calleds_dict = {}
    for i in xrange(len(sorted)):
        calleds_dict[sorted[i]] = i
    for i in xrange(len(calleds)):
        calleds[i] = calleds_dict[calleds[i]]
    return

def hashProcedures(calleds):
    handleCalledFunctions(calleds)
    s = ""
    for fn in calleds:
        s += str(fn) + ","
    h = hashlib.md5(s)
    dig = h.digest()
    if __DEBUG__:
        print "Procedures : " + s
        print "    MD5: " + dig.encode("hex")
    return dig


