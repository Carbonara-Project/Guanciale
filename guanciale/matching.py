#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, rop2bash@gmail.com"

import sys
import datasketch
import carbonara_archinfo as archinfo
import carbonara_pyvex as pyvex

if sys.version_info[0] < 3:
    range = xrange

r2_arch_map = {
    ("arm", 64): archinfo.ArchAArch64,
    ("arm", 32): archinfo.ArchARM,
    ("x86", 64): archinfo.ArchAMD64,
    #("avr", 16): archinfo.ArchAVR,
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
    #("avr", 16): archinfo.ArchAVR, #??? check if it is true in ida -> Manco per cazzo -> pls drop avr support
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


class StrConst(pyvex.const.IRConst):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


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
        #bb.append(self.offset + self.size)
        bb.append(self.size)
        consts = {}
        ips = []
        
        pc_offset = self.arch.registers["pc"][0]
        regs = {}
        irsbs = []

        for bidx in range(len(bb) -1):
            irsb = pyvex.IRSB(self.code[bb[bidx]:bb[bidx+1]], self.offset + bb[bidx], self.arch, opt_level=0)
            irsbs.append(irsb)
        
            stmts = irsb.statements
            n_addr = 0
            
            for i in range(len(stmts)):
                #TODO PutI GetI
                if isinstance(stmts[i], pyvex.stmt.IMark):
                    n_addr = stmts[i].addr + stmts[i].len
                elif isinstance(stmts[i], pyvex.stmt.Put):
                    if stmts[i].offset == pc_offset and len(stmts[i].constants) == 1:
                        c = stmts[i].constants[0]
                        if c.value in self.targets:
                            stmts[i].data = StrConst(self.targets[c.value])
                            #stmts[i].reg_name = "_PC_"
                            stmts[i] = stmts[i].__str__("_PC_")
                            continue
                        elif i+1 < len(stmts) and isinstance(stmts[i+1], pyvex.stmt.IMark) and stmts[i+1].addr == n_addr:
                            stmts[i].data = StrConst("_NEXT_")
                            stmts[i] = stmts[i].__str__("_PC_")
                            continue
                        else:
                            ips.append(c.value)
                            stmts[i].reg_name = "@"
                    else:
                        # constants replace
                        for j in range(len(stmts[i].constants)):
                            if stmts[i].constants[j].value in self.targets:
                                stmts[i].constants[j] = StrConst(self.targets[stmts[i].constants[j].value])
                        
                        # registers abstraction
                        regs[stmts[i].offset] = regs.get(stmts[i].offset, len(regs))
                        stmts[i].offset = regs[stmts[i].offset]
                elif isinstance(stmts[i], pyvex.stmt.Exit):
                    c = stmts[i].dst
                    if c.value in self.targets:
                        stmts[i] = "if (%s) { PUT(_PC_) = %s; %s }" % (stmts[i].guard, self.targets[c.value], stmts[i].jumpkind)
                        continue
                    else:
                        ips.append(c.value)
                        stmts[i].reg_name = "$"
                else:
                    # constants replace
                    for j in range(len(stmts[i].constants)):
                        if stmts[i].constants[j].value in self.targets:
                            stmts[i].constants[j] = StrConst(self.targets[stmts[i].constants[j].value])
                for expr in stmts[i].expressions:
                    if isinstance(expr, pyvex.expr.Get):
                        # registers abstraction
                        regs[expr.offset] = regs.get(expr.offset, len(regs))
                        expr.offset = regs[expr.offset]

        #order addresses
        addrs = {}
        ips.sort()
        for i in range(len(ips)):
            addrs[ips[i]] = i
        
        vexhash = datasketch.MinHash(num_perm=64)
        #vex_code = []
        
        for irsb in irsbs:
            stmts = irsb.statements
            
            for i in range(len(stmts)):
                if isinstance(stmts[i], pyvex.stmt.IMark) or isinstance(stmts[i], pyvex.stmt.AbiHint):
                    continue
                
                if hasattr(stmts[i], "reg_name"):
                    if stmts[i].reg_name == "@":
                        stmts[i].constants[0].value = addrs[stmts[i].constants[0].value]
                        stmts[i] = stmts[i].__str__("_PC_")
                    elif stmts[i].reg_name == "$":
                        stmts[i].dst.value = addrs[stmts[i].dst.value]
                        stmts[i] = stmts[i].__str__("_PC_")
                
                #vex_code.append(str(stmts[i]))
                vexhash.update(str(stmts[i]))
        
        lean_vexhash = datasketch.LeanMinHash(vexhash)
        vexhash_buf = bytearray(lean_vexhash.bytesize())
        lean_vexhash.serialize(vexhash_buf)
        
        self.vexhash = str(vexhash_buf)
        '''
        for v in vex_code:
            print v
        print
        print
        '''

    def liftByInsns(self):
        consts = {}
        ips = []
        #vex_code = []
        
        pc_offset = self.arch.registers["pc"][0]
        regs = {}
        irsbs = []

        for instr in self.insns_list:
            #manage instruction not recognized by libVEX
            if self.arch.name == "X86" or self.arch.name == "AMD64":
                if instr == "\xf4": #hlt x86 instruction
                    irsbs.append("HALT")
                    continue
                elif instr.startswith("\xf0"): #lock x86 prefix
                    irsbs.append("LOCK")
                    if len(instr) == 1:
                        continue
                    instr = instr[1:]
            try:
                irsb = pyvex.IRSB(instr, 0, self.arch, opt_level=0)
            except pyvex.errors.PyVEXError as err:
                print("Error with instruction " + instr.encode("hex"))
                raise err
            irsbs.append(irsb)
        
            stmts = irsb.statements
            n_addr = 0
            
            for i in range(len(stmts)):
                #TODO PutI GetI
                if isinstance(stmts[i], pyvex.stmt.IMark):
                    n_addr = stmts[i].addr + stmts[i].len
                elif isinstance(stmts[i], pyvex.stmt.Put):
                    if stmts[i].offset == pc_offset and len(stmts[i].constants) == 1:
                        c = stmts[i].constants[0]
                        if c.value in self.targets:
                            stmts[i].data = StrConst(self.targets[c.value])
                            #stmts[i].reg_name = "_PC_"
                            stmts[i] = stmts[i].__str__("_PC_")
                            continue
                        elif i+1 < len(stmts) and isinstance(stmts[i+1], pyvex.stmt.IMark) and stmts[i+1].addr == n_addr:
                            stmts[i].data = StrConst("_NEXT_")
                            stmts[i] = stmts[i].__str__("_PC_")
                            continue
                        else:
                            ips.append(c.value)
                            stmts[i].reg_name = "@"
                    else:
                        # constants replace
                        for j in range(len(stmts[i].constants)):
                            if stmts[i].constants[j].value in self.targets:
                                stmts[i].constants[j] = StrConst(self.targets[stmts[i].constants[j].value])
                        
                        # registers abstraction
                        regs[stmts[i].offset] = regs.get(stmts[i].offset, len(regs))
                        stmts[i].offset = regs[stmts[i].offset]
                elif isinstance(stmts[i], pyvex.stmt.Exit):
                    c = stmts[i].dst
                    if c.value in self.targets:
                        stmts[i] = "if (%s) { PUT(_PC_) = %s; %s }" % (stmts[i].guard, self.targets[c.value], stmts[i].jumpkind)
                        continue
                    else:
                        ips.append(c.value)
                        stmts[i].reg_name = "$"
                else:
                    # constants replace
                    for j in range(len(stmts[i].constants)):
                        if stmts[i].constants[j].value in self.targets:

                            stmts[i].constants[j] = StrConst(self.targets[stmts[i].constants[j].value])
                for expr in stmts[i].expressions:
                    if isinstance(expr, pyvex.expr.Get):
                        # registers abstraction
                        regs[expr.offset] = regs.get(expr.offset, len(regs))
                        expr.offset = regs[expr.offset]

        #order addresses
        addrs = {}
        ips.sort()
        for i in range(len(ips)):
            addrs[ips[i]] = i
        
        vexhash = datasketch.MinHash(num_perm=64)
        
        for irsb in irsbs:
            if type(irsb) == type(""):
                #vex_code.append(irsb)
                vexhash.update(irsb)
                continue
            
            stmts = irsb.statements
            
            for i in range(len(stmts)):
                if isinstance(stmts[i], pyvex.stmt.IMark) or isinstance(stmts[i], pyvex.stmt.AbiHint):
                    continue
                
                if hasattr(stmts[i], "reg_name"):
                    if stmts[i].reg_name == "@":
                        stmts[i].constants[0].value = addrs[stmts[i].constants[0].value]
                        stmts[i] = stmts[i].__str__("_PC_")
                    elif stmts[i].reg_name == "$":
                        stmts[i].dst.value = addrs[stmts[i].dst.value]
                        stmts[i] = stmts[i].__str__("_PC_")
                
                #vex_code.append(str(stmts[i]))
                vexhash.update(str(stmts[i]))
        
        lean_vexhash = datasketch.LeanMinHash(vexhash)
        vexhash_buf = bytearray(lean_vexhash.bytesize())
        lean_vexhash.serialize(vexhash_buf)
        
        self.vexhash = str(vexhash_buf)

    def lift(self):
        try:
            self.liftByBlocks()
        except pyvex.errors.PyVEXError as err:
            #print err
            self.liftByInsns()       
        
    
    def handleFlow(self):
        
        #TODO replace sorting loops with sorted function
        self.targets = {}
        self.api = []
        #flow = []
        
        addrs = []
        internals = []
        
        for instr in self.bb_insns:
            if isinstance(instr, CallInsn):
                if instr.is_api:
                    self.targets[instr.addr] = "API:" + instr.fcn_name
                    
                    self.api.append({"name": instr.fcn_name})
                else:
                    internals.append(instr.addr)
                    
            else:
                if instr.jumpout:
                    internals.append(instr.addr)
                else:
                    addrs.append(instr.addr)
                    addrs.append(instr.offset)
        
        addrs.sort()
        addrs_dict = {}
        for i in range(len(addrs)):
            addrs_dict[addrs[i]] = i
        
        internals_sorted = internals[:]
        internals_sorted.sort()
        calleds_dict = {}
        for i in range(len(internals_sorted)):
            calleds_dict[internals_sorted[i]] = str(i)
            
        flowhash = datasketch.MinHash(num_perm=32)
        
        for instr in self.bb_insns:
            if isinstance(instr, CallInsn):
                if instr.is_api:
                    #flow.append(hex(instr.offset)+"  API:" + instr.fcn_name)
                    flowhash.update("API:" + instr.fcn_name)
                else:
                    #flow.append(hex(instr.offset)+"  OUT:" + calleds_dict[instr.addr])
                    flowhash.update("OUT:" + calleds_dict[instr.addr])
                    self.targets[instr.addr] = "OUT:" + calleds_dict[instr.addr]
            else:
                if instr.jumpout:
                    #flow.append(hex(instr.offset)+"  OUT:" + calleds_dict[instr.addr])
                    flowhash.update("OUT:" + calleds_dict[instr.addr])
                    self.targets[instr.addr] = "OUT:" + calleds_dict[instr.addr]
                else:
                    off = addrs_dict[instr.offset]
                    tgt = addrs_dict[instr.addr]
                    #flow.append("%x (%d)   JMP:%s   - %x (%d)" % (instr.offset, off, str(tgt - off), instr.addr, tgt))
                    flowhash.update("JMP:" + str(tgt - off))
                    self.targets[instr.addr] = "JMP:" + str(tgt - off)
        
        lean_flowhash = datasketch.LeanMinHash(flowhash)
        flowhash_buf = bytearray(lean_flowhash.bytesize())
        lean_flowhash.serialize(flowhash_buf)
        
        self.flowhash = str(flowhash_buf)
        '''
        for f in flow:
            print f
        for pp in self.bb_insns:
            print pp
        '''

    """
    def handleFlow(self):
        
        #TODO replace sorting loops with sorted function
        api = []
        internals = []
        jumps = []
        api_str = ""

        self.targets = {}
        self.api = []
        #self.flow = []
        
        for instr in self.bb_insns:
            if isinstance(instr, CallInsn):
                if instr.is_api:
                    self.targets[instr.addr] = "API:" + instr.fcn_name
                    
                    self.api.append({"name": instr.fcn_name})
                else:
                    internals.append(instr.addr)
                    
            else:
                if instr.addr not in self.targets:
                    if instr.jumpout:
                        internals.append(instr.addr)
                    else:
                        jumps.append(instr.addr)
        
        jumps.sort()
        jumps_dict = {}
        for i in range(len(jumps)):
            jumps_dict[jumps[i]] = i
            
            self.targets[jumps[i]] = "JMP:" + str(i)
        
        internals_sorted = internals[:]
        internals_sorted.sort()
        calleds_dict = {}
        for i in range(len(internals_sorted)):
            calleds_dict[internals_sorted[i]] = str(i)
            
            self.targets[internals_sorted[i]] = "OUT:" + hex(i)
        
        flowhash = datasketch.MinHash(num_perm=32)
        
        for instr in self.bb_insns:
            if isinstance(instr, CallInsn):
                if instr.is_api:
                    #self.flow.append("API:" + instr.fcn_name)
                    flowhash.update("API:" + instr.fcn_name)
                else:
                    #self.flow.append("OUT:" + calleds_dict[instr.addr])
                    flowhash.update("OUT:" + calleds_dict[instr.addr])
            else:
                if instr.addr not in self.targets:
                    if instr.jumpout:
                        #self.flow.append("OUT:" + calleds_dict[instr.addr])

                        flowhash.update("OUT:" + calleds_dict[instr.addr])
                    else:
                        #self.flow.append("JMP:" + jumps_dict[instr.addr])
                        flowhash.update("JMP:" + jumps_dict[instr.addr])
        
        lean_flowhash = datasketch.LeanMinHash(flowhash)
        flowhash_buf = bytearray(lean_flowhash.bytesize())
        lean_flowhash.serialize(flowhash_buf)
        
        self.flowhash = str(flowhash_buf)
        
        '''
        for f in self.flow:
            print f
        '''
    """
