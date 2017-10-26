import pyvex
import archinfo
import hashlib

vex_arch_map = {
    "AMD64": archinfo.ArchAMD64,
    
}


class AbstractProcedure(object):
    def __init__(code, offset, size):
        self.code = code
        self.offset = offset
        self.size = size
    
    def lift_helper(self, irsb):
        
    
    def lift(self):
        self.consts = {}
        self.regs = {}
        self.ips = []
        self.vexcode = ""
        
        irsb = pyvex.IRSB(self.code, offset, archinfo.ArchAMD64())
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


