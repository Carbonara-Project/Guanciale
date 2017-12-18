import r2pipe
import config
import matching
import sys
import status
import hashlib
import base64
import os
from errors import *

def printerr(s):
    sys.stderr.write(str(s) + "\n")

_MODE_R2 = 0
_MODE_IDA = 1
_MODE_IDB = 2

R2PLUGIN = 0xABADCAFE

class BinaryInfo(object):

    def __init__(self, filename):
        
        if filename == R2PLUGIN:
            self.r2 = r2pipe.open("#!pipe")
            filename = self.r2.cmdj("oj")["uri"]
        else:
            self.r2 = r2pipe.open(filename)
        
        #open the binary file and compute md5 and sha256 hash
        binfile = open(filename, "rb")
        self.content = binfile.read()
        
        hash_object = hashlib.md5(self.content)
        md5_dig = hash_object.hexdigest()
        hash_object = hashlib.sha256(self.content)
        sha256_dig = hash_object.hexdigest()
        
        binfile.close()
        
        self.md5 = md5_dig
        
        self.data = {
            "program": {
                "md5": md5_dig,
                "sha256": sha256_dig
            },
            "procs": [],
            "codebytes": {}
        }
        
         #get  binary properties
        self.data["info"] = self.r2.cmdj('iIj')
        self.data["info"]["program_class"] = self.data["info"]["class"] #rename for the backend
        del self.data["info"]["class"]
        
        self.data["info"]["filename"] = filename
    
    def __del__(self):
        if hasattr(self, "r2"):
            self.r2.quit()
    
    
    def addAdditionalInfo(self):
        #get sections
        r2_sections = self.r2.cmdj('iSj')
        
        self.data["sections"] = []
        for sec in r2_sections:
            offset = sec["paddr"]
            size = sec["size"]
            
            #calculate md5 of the section
            hash_object = hashlib.md5(self.content[offset: offset + size])
            hex_dig = hash_object.hexdigest()
            
            s = {
                "name": sec["name"],
                "offset": offset,
                "size": size,
                "md5": hex_dig
            }
            self.data["sections"].append(s)
        
        #calculate entropy
        r2_entropy = self.r2.cmdj('p=ej') #TODO ??? must be rewritten!!! listen ML experts
        self.data["entropy"] = { "addr_value_list" : r2_entropy["entropy"] }
        
        
    def addStrings(self):
        #get strings contained in the binary
        r2_strings = self.r2.cmdj('izzj')["strings"]
        
        self.data["strings"] = []
        for strg in r2_strings:
            s = {
                "val": strg["string"],
                "offset": strg["paddr"],
                "size": strg["size"],
                "encoding": strg["type"]
            }
            self.data["strings"].append(s)
    
    
    def grabProcedures(self, engine, database=None):
        engine = engine.lower()
        if engine == "radare2":
            if database:
                self._fromR2Project(database)
            else:
                self._generateR2()
            self._mode = _MODE_R2
        elif engine == "idapro":
            if database == None:
                raise RuntimeError("BinaryInfo.grabProcedures: using IDA Pro as engine you must specify the database file!")
            if config.idacmd:
                self._fromIDAPro(database)
                self._mode = _MODE_IDA
            else:
                self._parseIDB(database)
                self._mode = _MODE_IDB
        else:
            raise RuntimeError("BinaryInfo.grabProcedures: invalid engine %s" % str(engine))
        
    
    def processSingle(self, procedure):
        pass
    
    
    def processAll(self):
        if self._mode == _MODE_R2:
            self.processProc = self._processR2Procedure
        elif self._mode == _MODE_IDA:
            self.processProc = self._processIDAProcedure
        elif self._mode == _MODE_IDB:
            self.processProc = self._processIDBProcedure
        else:
            raise RuntimeError("BinaryInfo.processAll: mode not valid")
        
        with status.Status(len(self.procs)) as bar:
            count = 0
            for proc in self.procs:
                try:
                    self.data["procs"].append(self.processProc(proc))
                except Exception as ee:
                    print ee
                    printerr("error on function %s, skipped" % proc["name"])
                count += 1
                bar.update(count)
        
        return self.data
    

    def _generateR2(self):
        #analyze all
        self.r2.cmd("aaa")
        self._grabR2Procedures()
    
    
    def _fromR2Project(self, filename):
        #set project directory var in radare
        projdir = os.path.dirname(filename)
        projname = os.path.basename(filename)
        if projdir != "":
            projdir = os.path.expanduser(projdir)
            self.r2.cmd("e dir.projects=" + projdir)
        
        #load project
        out = self.r2.cmd("Po " + projname)
        if "Cannot open project info" in out:
            raise RuntimeError("BinaryInfo._fromR2Project: cannot load radare2 project " + name)
        self._grabR2Procedures()
    
    
    def _grabR2Procedures(self):
        #map architecture
        try:
            self.arch = matching.archFromR2(self.data["info"]["arch"], self.data["info"]["bits"], self.data["info"]["endian"])
        except:
            raise ArchNotSupported("arch %s not supported" % self.data["info"]["arch"])
        self.data["info"]["arch"] = self.arch.name
        
        libs_list = self.r2.cmdj('ilj')
        self.libs = []
        for lib in libs_list:
            self.libs.append({"name": lib})
        
        #get imported functions
        imports = self.r2.cmdj('iij')
        
        self.data["imports"] = []
        imports_dict = {}
        for imp in imports:
            i = {
                "name": imp["name"],
                "addr": imp["plt"] #??? for PE binaries?
            }
            for lib in libs_list:
                if len(imp["name"]) > len(lib) and imp["name"][:len(lib)] == lib:
                    imports_dict[imp["name"][len(lib):]] = imp["plt"]
                    break
            
            self.data["imports"].append(i)
        
        #get exported symbols
        exports = self.r2.cmdj('iEj')
        
        self.data["exports"] = []
        for exp in exports:
            e = {
                "name": exp["name"],
                "offset": exp["paddr"],
                "size": exp["size"]
            }
            self.data["exports"].append(e)

        #get info about analyzed functions
        funcs_dict = self.r2.cmdj('aflj')
        sym_imp_l = len("sym.imp") 
        
        self.procs = []
        self.procs_names = {}
        self.procs_addrs = {}
        
        for func in funcs_dict:
            try:
                #skip library symbols
                if len(func["name"]) >= sym_imp_l and func["name"][:sym_imp_l] == "sym.imp":
                    continue
                
                #get assembly from a function 
                fcn_instructions = self.r2.cmdj('pdrj')
                
                #r2 cmd p6e : get bytes of a function in base64
                fcn_bytes = base64.b64decode(self.r2.cmd('p6e ' + str(func["size"])).rstrip())
                
                self.procs_names[func["name"]] = len(self.procs)
                self.procs_addrs[func["offset"]] = len(self.procs)
                
                self.procs.append({
                    "offset": func["offset"],
                    "name": func["name"],
                    "size": func["size"],
                    "calltype": func["calltype"],
                    "instructions": fcn_instructions,
                    "bytes": fcn_bytes
                })
            except Exception as ee:
                print "P", ee
                printerr("error on function %s, skipped" % func["name"])
    
    
    def _processR2Procedure(self, proc_info):
        insns_list = []
        asm = ""
        
        flow_insns = []
        targets = {}
        
        fcn_offset = proc_info["offset"]
        fcn_size = proc_info["size"]
        sym_imp_l = len("sym.imp") 
        
        for instr in proc_info["instructions"]:
            if instr["type"] == "invalid":
                break
            
            #get the first byte in hex
            first_byte = instr["bytes"][:2]

            #insert ops in codebytes (field with the frequency of each opcode, useful for ML)
            self.data["codebytes"][first_byte] = self.data["codebytes"].get(first_byte, 0) +1
            
            #insert comments in disassembly if presents
            if "comment" in instr:
                asm += hex(instr["offset"]) + "   " + instr["opcode"] + "  ; " + base64.b64decode(instr["comment"]) + "\n"
            else:
                asm += hex(instr["offset"]) + "   " + instr["opcode"] + "\n"
                
            #check if the instruction is of type 'call'
            if instr["type"] == "call" and "jump" in instr:
                target_name = instr["opcode"].split()[-1]
                call_instr = None
                if target_name[:sym_imp_l] == "sym.imp":
                    call_instr = matching.CallInsn(instr["offset"], instr["size"], instr["jump"], target_name[sym_imp_l +1:], True)
                elif target_name[:len("sub.")] == "sub.":
                    call_instr = matching.CallInsn(instr["offset"], instr["size"], instr["jump"], target_name[len("sub."):], True)
                elif target_name[:len("sym.")] == "sym." and target_name[len("sym."):] in imports_dict:
                    call_instr = matching.CallInsn(instr["offset"], instr["size"], instr["jump"], target_name[len("sym."):], True)
                else:
                    call_instr = matching.CallInsn(instr["offset"], instr["size"], instr["jump"], target_name)
                flow_insns.append(call_instr)
                
            #check if the instruction is of type 'jump'
            elif (instr["type"] == "cjmp" or instr["type"] == "jmp") and "jump" in instr:
                target = instr["jump"]
                jumpout = target < fcn_offset or target >= (fcn_offset + fcn_size)
                jump_instr = matching.JumpInsn(instr["offset"], instr["size"], target, jumpout)
                flow_insns.append(jump_instr)
            
            insns_list.append(instr["bytes"].decode("hex"))
        
        handler = matching.ProcedureHandler(proc_info["bytes"], insns_list, proc_info["offset"], flow_insns, self.arch)
        handler.handleFlow()
        handler.lift()

        proc_dict = {
            "offset": fcn_offset,
            "proc_desc": {
                "name": proc_info["name"],
                "raw": base64.b64encode(proc_info["bytes"]),
                "asm": asm,
                "callconv": proc_info["calltype"],
                "apicalls": handler.api,
                "arch": self.arch.name
            }
        }
        
        proc_dict["proc_desc"]["flow_hash"] = handler.flowhash.encode("hex")
        proc_dict["proc_desc"]["vex_hash"] = handler.vexhash.encode("hex")
        proc_dict["proc_desc"]["full_hash"] = hashlib.md5(proc_info["bytes"]).hexdigest()
        
        return proc_dict




