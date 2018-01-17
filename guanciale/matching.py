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
    def __init__(self, insns_list, bb_insns, arch):
        self.insns_list = insns_list
        self.bb_insns = bb_insns
        self.arch = arch


    def work(self):
        self.handleFlow()
        self.handleInsns()

    def handleInsns(self):
        consts = {}
        ips = []
        
        #set dafaukt value for PC, SP, BP
        pc_offset = self.arch.ip_offset
        regs = {
            pc_offset: 0,
            self.arch.sp_offset: 1,
            self.arch.bp_offset: 2
        }
        consts = {}
        irsbs = []

        for instr_c in range(len(self.insns_list)):
            off = self.insns_list[instr_c][0]
            instr = self.insns_list[instr_c][1]
            
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
                irsb = pyvex.IRSB(instr, off, self.arch, opt_level=0)
            except pyvex.errors.PyVEXError as err:
                print("[Please report to the developer] Error with instruction " + instr.encode("hex"))
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
                            stmts[i].offset = 0
                            continue
                        elif c.value == n_addr:
                            stmts[i].data = StrConst("_NEXT_")
                            stmts[i].offset = 0
                            continue
                        else:
                            ips.append(c.value)
                            stmts[i].reg_name = 0xABADCAFE
                            stmts[i].offset = 0
                    else:
                        # constants replace
                        for j in range(len(stmts[i].constants)):
                            c = stmts[i].constants[j]
                            if c.value in self.targets:
                                stmts[i].constants[j] = StrConst(self.targets[c.value])
                            elif c.value == n_addr:
                                stmts[i].constants[j] = StrConst("_NEXT_")
                            else:
                                # constants abstraction
                                consts[c.value] = consts.get(c.value, len(consts))
                                c.value = consts[c.value]
                        
                        # registers abstraction
                        regs[stmts[i].offset] = regs.get(stmts[i].offset, len(regs))
                        stmts[i].offset = regs[stmts[i].offset]
                elif isinstance(stmts[i], pyvex.stmt.Exit):
                    c = stmts[i].dst
                    if c.value in self.targets:
                        stmts[i] = "if (%s) { PUT(offset=0) = %s; %s }" % (stmts[i].guard, self.targets[c.value], stmts[i].jumpkind)
                        continue
                    else:
                        ips.append(c.value)
                        stmts[i].reg_name = 0xDEADBEEF
                else:
                    # constants replace
                    for j in range(len(stmts[i].constants)):
                        c = stmts[i].constants[j]
                        if c.value in self.targets:
                            stmts[i].constants[j] = StrConst(self.targets[c.value])
                        elif c.value == n_addr:
                            stmts[i].constants[j] = StrConst("_NEXT_")
                        else:
                            # constants abstraction
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
        for i in range(len(ips)):
            addrs[ips[i]] = i
        
        #self.vex_code = ""
        #self.shingled_code = ""
        
        vexhash = datasketch.MinHash(num_perm=64)
        shingled = {}
        last = ""
        
        for c in range(len(irsbs)):
            irsb = irsbs[c]
            
            if type(irsb) == type(""):
                ngram = last + irsb
                #self.vex_code += "+++ Instr #%d +++\n%s\n" % (c, irsb)
                shingled[ngram] = shingled.get(ngram, 0) +1
                last = irsb
                continue
            
            stmts = irsb.statements
            ins = ""
            
            for i in range(len(stmts)):
                if isinstance(stmts[i], pyvex.stmt.IMark) or isinstance(stmts[i], pyvex.stmt.AbiHint):
                    continue
                
                if hasattr(stmts[i], "reg_name"):
                    if stmts[i].reg_name == 0xABADCAFE:
                        stmts[i].constants[0].value = addrs[stmts[i].constants[0].value]
                    elif stmts[i].reg_name == 0xDEADBEEF:
                        stmts[i].dst.value = addrs[stmts[i].dst.value]
                
                v = str(stmts[i]) + "\n"
                ins += v
                ngram = last + v
                shingled[ngram] = shingled.get(ngram, 0) +1
                last = v
            
            #self.vex_code += "+++ Instr #%d +++\n%s\n" % (c, ins)
        
        for ngram in shingled:
            for c in range(shingled[ngram]):
                vexhash.update("[%d]\n%s" % (c, ngram))
                #self.shingled_code += "[%d]\n%s" % (c, ngram)
        
        lean_vexhash = datasketch.LeanMinHash(vexhash)
        vexhash_buf = bytearray(lean_vexhash.bytesize())
        lean_vexhash.serialize(vexhash_buf)
        
        self.vexhash = str(vexhash_buf)
        
        
    
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

