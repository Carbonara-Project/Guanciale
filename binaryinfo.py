#import idblib #https://github.com/nlitsme/pyidbutil
import json
import base64
import our_r2pipe
import hashlib

class Procedure(object):
    def __init__(self, asm, raw, ops, offset):
        '''
        Procedure

        :param str asm: The disassembly with comments
        :param str raw: The bytes of the function
        :param str ops: List of first bytes of each instruction
        :param integer offset: The offset of function from the binary base address
        '''
        
        self.data = {
            "asm": asm,
            "offset": offset
        }
        #hash of level 1: sha256 of the first bytes of each instruction
        hash_object = hashlib.sha256(ops)
        hex_dig = hash_object.hexdigest()
        self.data["hash1"] = hash_object.hexdigest()
        #hash of level 2: sha256 of the entire function code
        hash_object = hashlib.sha256(raw)
        hex_dig = hash_object.hexdigest()
        self.data["hash2"] = hash_object.hexdigest()
        #convert the function code to base64 
        self.data["raw"] = base64.b64encode(raw)
    
    def toJson(self):
        return json.dumps(self.data, ensure_ascii=True, indent=4, cls=_JsonEncoder)

    def __str__(self):
        return self.toJson()


class BinaryInfo(object):
    def __init__(self, filename):
        '''
        BinaryInfo

        :param str filename: The filename of target binary
        '''
        
        self.data = {
            "procs": {},
            "strings": [],
            "r2info": {}
        }
        #open radare2 as subprocess
        self.r2 = our_r2pipe.open(filename)
        #r2 cmd ij : get info about binary in json
        info = self.r2.cmdj('ij')
        self.data["r2info"] = info["bin"]

    def __del__(self):
        self.r2.quit()

    def addProc(self, name, proc):
        self.data["procs"][name] = proc
    
    def addString(self, string):
        self.data["strings"].append(string)
    
    def toJson(self):
        return json.dumps(self.data, ensure_ascii=True, indent=4, cls=_JsonEncoder)
    
    def __str__(self):
        return self.toJson()
    
    def fromIdb(self, filename):
        '''
        Get information about binary stored in a IDA database

        :param str filename: The filename of the associated IDA database
        '''
        #...
        pass
    
    def generateInfo(self):
        '''
        Grab basic informations about the binary from r2
        '''
        
        #r2 cmd aa : analyze all
        self.r2.cmd('aa')
        #r2 cmd izzj : get strings contained in the binary in json
        self.data["strings"] = self.r2.cmdj('izzj')
        #r2 cmd aflj : get info about analyzed functions
        funcs_dict = self.r2.cmdj('aflj')
        l = len("sym.imp")
        for func in funcs_dict:
            #skip library symbols
            if len(func["name"]) >= l and func["name"][:l] == "sym.imp":
                continue
            offset = func["offset"]
            #r2 cmd pdfj : get assembly from a function in json
            asmj = self.r2.cmdj('pdfj @ ' + func["name"])
            #r2 cmd prf : get bytes of a function
            raw = self.r2.cmd('prf @ ' + func["name"])
            
            asm = ""
            ops = ""
            for instr in asmj["ops"]:
                ops += instr["bytes"][:2]
                if "comment" in instr:
                    asm += instr["opcode"] + "  ; " + base64.b64decode(instr["comment"]) + "\n"
                else:
                    asm += instr["opcode"] + "\n"
            
            self.addProc(func["name"], Procedure(asm, raw, ops.decode("hex"), offset))


class _JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, BinaryInfo) or isinstance(obj, Procedure): 
            return obj.data
        return json.JSONEncoder.default(self, obj)


if __name__ == "__main__":
    import sys
    bi = BinaryInfo(sys.argv[1])
    bi.generateInfo()
    j = bi.toJson()
    print j
    
