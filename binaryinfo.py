#import idblib #https://github.com/nlitsme/pyidbutil
import json
import base64
import our_r2pipe
import hashlib

class Procedure(object):
    def __init__(self, asm, raw, ops, offset):
        self.data = {
            "asm": asm,
            "offset": offset
        }
        hash_object = hashlib.sha256(ops)
        hex_dig = hash_object.hexdigest()
        self.data["hash1"] = hash_object.hexdigest()
        hash_object = hashlib.sha256(raw)
        hex_dig = hash_object.hexdigest()
        self.data["hash2"] = hash_object.hexdigest()
        self.data["raw"] = base64.b64encode(raw)
    
    def toJson(self):
        return json.dumps(self.data, ensure_ascii=True, indent=4, cls=_JsonEncoder)

    def __str__(self):
        return self.toJson()


class BinaryInfo(object):
    def __init__(self, filename):
        self.data = {
            "procs": {},
            "strings": [],
            "r2info": {}
        }
        self.r2 = our_r2pipe.open(filename)
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
        #...
        pass
    
    def generateInfo(self):
        self.r2.cmd('aa')
        self.data["strings"] = self.r2.cmdj('izzj')
        funcs_dict = self.r2.cmdj('aflj')
        l = len("sym.imp")
        for func in funcs_dict:
            if len(func["name"]) >= l and func["name"][:l] == "sym.imp":
                continue
            offset = func["offset"]
            asmj = self.r2.cmdj('pdfj @ ' + func["name"])
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
    
