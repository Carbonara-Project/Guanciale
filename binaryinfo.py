#import idblib #https://github.com/nlitsme/pyidbutil
import json
import base64
import our_r2pipe
import hashlib

class Function(object):
    def __init__(self, asm, raw, offset):
        self.data = {
            "asm": asm,
            "offset": offset
        }
        hash_object = hashlib.sha256(raw)
        hex_dig = hash_object.hexdigest()
        self.data["hash"] = hash_object.hexdigest()
        self.data["raw"] = base64.b64encode(raw)
    
    def toJson(self):
        return json.dumps(self.data, ensure_ascii=True, indent=4, cls=_JsonEncoder)

    def __str__(self):
        return self.toJson()


class BinaryInfo(object):
    def __init__(self, filename):
        self.data = {
            "funcs": {},
            "strings": [],
            "r2info": {}
        }
        self.r2 = our_r2pipe.open(filename)
        self.r2.cmd('aa')
        info = self.r2.cmdj('ij')
        self.data["r2info"] = info["bin"]

    def __del__(self):
        self.r2.quit()

    def addFunc(self, name, func):
        self.data["funcs"][name] = func
    
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
        self.data["strings"] = self.r2.cmdj('izzj')
        funcs_dict = self.r2.cmdj('aflj')
        l = len("sym.imp")
        for func in funcs_dict:
            if len(func["name"]) >= l and func["name"][:l] == "sym.imp":
                continue
            offset = func["offset"]
            asm = self.r2.cmd('pdf @ ' + func["name"])
            raw = self.r2.cmd('prf @ ' + func["name"])
            self.addFunc(func["name"], Function(asm, raw, offset))


class _JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, BinaryInfo) or isinstance(obj, Function): 
            return obj.data
        return json.JSONEncoder.default(self, obj)


if __name__ == "__main__":
    import sys
    bi = BinaryInfo(sys.argv[1])
    bi.generateInfo()
    j = bi.toJson()
    #print j
    
