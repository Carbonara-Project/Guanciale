import r2pipe
import config
import matching
import sys
import status
import hashlib
import base64
import os
import json
import subprocess
import random
import string
from errors import *

def printerr(s):
    sys.stderr.write(str(s) + "\n")

def printout(s):
    sys.stdout.write(s)
    sys.stdout.flush()

_MODE_R2 = 0
_MODE_IDA = 1
_MODE_IDB = 2

R2PLUGIN = 0xABADCAFE

class BinaryInfo(object):

    def _cmd_j(self, cmd):
        o = self.r2.cmd(cmd)
        try:
            r = json.loads(o)
        except:
            return None
        return r

    def __init__(self, filename):
        
        if filename == R2PLUGIN:
            self.r2 = r2pipe.open("#!pipe")
            oj = self._cmd_j("oj")
            if oj == None:
                raise RuntimeError("BinaryInfo.__init__: please open a file in radare2!")
            filename = oj[0]["uri"]
            self.r2plugin = True
            print " >> Working on %s as radare2 plugin" % filename
        else:
            self.r2 = r2pipe.open(filename)
        
        #open the binary file and compute md5 and sha256 hash
        printout(" [ ] Computing hashes of the entire binary")
        binfile = open(filename, "rb")
        self.content = binfile.read()
        
        hash_object = hashlib.md5(self.content)
        md5_dig = hash_object.hexdigest()
        hash_object = hashlib.sha256(self.content)
        sha256_dig = hash_object.hexdigest()
        
        binfile.close()
        printout("\r [*] Computing hashes of the entire binary\n")
        
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
        printout(" [ ] Getting basic properties from the binary")
        self.data["info"] = self._cmd_j('iIj')
        self.data["info"]["program_class"] = self.data["info"]["class"] #rename for the backend
        del self.data["info"]["class"]
        
        self.data["info"]["filename"] = filename
        self.filename = filename
        printout("\r [*] Getting basic properties from the binary\n")
        
    
    def __del__(self):
        if hasattr(self, "r2"):
            self.r2.quit()
    
    
    def addAdditionalInfo(self):
        #get sections
        printout(" [ ] Extracting info about sections")
        r2_sections = self._cmd_j('iSj')
        
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
        printout("\r [*] Extracting info about sections\n")
        
        #calculate entropy
        printout(" [ ] Calculating entropy")
        r2_entropy = self._cmd_j('p=ej') #TODO ??? must be rewritten!!! listen ML experts
        self.data["entropy"] = { "addr_value_list" : r2_entropy["entropy"] }
        printout("\r [*] Calculating entropy\n")
        
        
    def addStrings(self):
        #get strings contained in the binary
        printout(" [ ] Getting strings")
        r2_strings = self._cmd_j('izzj')["strings"]
        
        self.data["strings"] = []
        for strg in r2_strings:
            s = {
                "val": strg["string"],
                "offset": strg["paddr"],
                "size": strg["size"],
                "encoding": strg["type"]
            }
            self.data["strings"].append(s)
        printout("\r [*] Getting strings\n")
    
    
    def grabProcedures(self, engine, database=None):
        engine = engine.lower()
        if engine == "radare2":
            if database:
                self._fromR2Project(database)
            elif hasattr(self, "r2plugin"):
                self._grabR2Procedures()
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
        
    
    def processSingle(self, proc_search):
        if self._mode == _MODE_R2:
            self.processProc = self._processR2Procedure
        elif self._mode == _MODE_IDA:
            self.processProc = self._processIDAProcedure
        elif self._mode == _MODE_IDB:
            self.processProc = self._processIDBProcedure
        else:
            raise RuntimeError("BinaryInfo.processSingle: mode not valid")
        
        printout(" [ ] Searching target procedure")
        for proc in self.procs:
            if proc["name"] == proc_search or hex(proc["offset"]) == proc_search or str(proc["offset"]) == proc_search:
                printout("\r [*] Searching target procedure\n")
                printout(" [ ] Processing target procedure")
                data = {
                    "program": self.md5,
                    "procedure": self.processProc(proc)
                }
                printout("\r [*] Processing target procedure\n")
                return data
        printout("\r [*] Searching target procedure\n")
        return None
    
    
    def processAll(self):
        if self._mode == _MODE_R2:
            self.processProc = self._processR2Procedure
        elif self._mode == _MODE_IDA:
            self.processProc = self._processIDAProcedure
        elif self._mode == _MODE_IDB:
            self.processProc = self._processIDBProcedure
        else:
            raise RuntimeError("BinaryInfo.processAll: mode not valid")
        
        print(" >> Processing all procedures")
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
        printout(" [ ] Analyzing all")
        self.r2.cmd("aaa")
        printout(" [*] Analyzing all\n")
        self._grabR2Procedures()
    
    
    def _fromR2Project(self, filename):
        printout(" [ ] Loading radare project")
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
        printout("\r [*] Loading radare project\n")
        
        self._grabR2Procedures()
    
    
    def _grabR2Procedures(self):
        #map architecture
        try:
            self.arch = matching.archFromR2(self.data["info"]["arch"], self.data["info"]["bits"], self.data["info"]["endian"])
        except:
            raise ArchNotSupported("arch %s not supported" % self.data["info"]["arch"])
        self.data["info"]["arch"] = self.arch.name
        
        printout(" [ ] Getting linked libraries")
        libs_list = self._cmd_j('ilj')
        self.libs = []
        for lib in libs_list:
            self.libs.append({"name": lib})
        printout("\r [*] Getting linked libraries\n")
        
        printout(" [ ] Getting imported functions")
        #get imported functions
        imports = self._cmd_j('iij')
        
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
        printout("\r [*] Getting imported functions\n")
        
        printout(" [ ] Getting exported symbols")
        #get exported symbols
        exports = self._cmd_j('iEj')
        
        self.data["exports"] = []
        for exp in exports:
            e = {
                "name": exp["name"],
                "offset": exp["paddr"],
                "size": exp["size"]
            }
            self.data["exports"].append(e)
        printout("\r [*] Getting exported symbols\n")
        
        #get analyzed functions list
        printout(" [ ] Getting procedures list")
        funcs_dict = self._cmd_j('aflj')
        printout("\r [*] Getting procedures list\n")
        
        if hasattr(self, "r2plugin"):
            if funcs_dict == None:
                print(" >> Procedure list is empty, performing an analysis with 'aaa'")
                #analyze all
                printout(" [ ] Analyzing all")
                self.r2.cmd("aaa")
                printout(" [*] Analyzing all\n")
                printout(" [ ] Getting procedures list (again)")
                funcs_dict = self._cmd_j('aflj')
                printout("\r [*] Getting procedures list (again)\n")
        
        if funcs_dict == None:
            raise RuntimeError("BinaryInfo._grabR2Procedures: cannot get list of procedures")
        
        sym_imp_l = len("sym.imp")
        
        printout(" [ ] Building procedures index (0/%d)" % len(funcs_dict))
        
        self.procs = []
        self.procs_names = {}
        self.procs_addrs = {}
        
        i = 1
        for func in funcs_dict:
            printout("\r [ ] Building procedures index (%d/%d)" % (i, len(funcs_dict)))
            try:
                #skip library symbols
                if len(func["name"]) >= sym_imp_l and func["name"][:sym_imp_l] == "sym.imp":
                    i += 1
                    continue
                
                #get assembly from a function 
                fcn_instructions = self._cmd_j('pdrj')
                
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
            i += 1
        printout("\r [*] Building procedures index\n")
    
    
    def _processR2Procedure(self, proc_info):
        insns_list = []
        asm = ""
        flow_insns = []
        
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


    def _fromIDAPro(self, filename):
        printout(" [ ] Waiting for IDA to parse database (this may take several minutes)...")
        
        binname = os.path.splitext(filename)[0]
        rand = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
        dumpname = '.'+binname+ '-'+ rand +'-dump.json'

        file_ext = os.path.splitext(filename)[1]
        idascript = os.path.join(os.path.dirname(os.path.abspath(__file__)), "idascript.py ")
        
        if config.usewine:
            idascript.replace(os.path.sep, "\\")
        
        if file_ext == '.idb':
            process = subprocess.Popen(config.idacmd + ' -A -S"' + idascript + dumpname +'" "' + filename + '"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif file_ext == '.i64':
            process = subprocess.Popen(config.ida64cmd + ' -A -S"' + idascript + dumpname +'" "' + filename + '"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            raise RuntimeError('BinaryInfo._fromIDAPro: extension %s is not supported' % file_ext)
        process.wait()
        
        #getting data from idascript via json
        idadump = open(dumpname, 'r')
        data = json.load(idadump)
        idadump.close()

        #clean up
        os.remove(dumpname)
        printout("\r [*] Waiting for IDA to parse database (this may take several minutes)...\n")
                
        printout(" [ ] Getting file properties and symbols")
        #self.data['info'] = data['info']
        for key in data['info']:
            self.data['info'][key] = data['info'][key]
        
        try:
            self.arch = matching.archFromIda(self.data["info"]["arch"], self.data["info"]["bits"], self.data["info"]["endian"])
        except:
            raise ArchNotSupported("arch %s not supported" % self.data["info"]["arch"])
        self.data["info"]["arch"] = self.arch.name
        
        self.data['libs'] = data['libs']

        self.data['imports'] = data['imports']

        self.data["exports"] = data['exports']
        printout("\r [*] Getting file properties and symbols\n")
        
        self.procs = data['procedures']


    def _processIDAProcedure(self, proc_info):
        fcn_bytes = base64.b64decode(proc_info['raw_data'])
        insns_list = []
        for ins in proc_info['insns_list']:
            insns_list.append(base64.b64decode(ins))
        opcodes_list = proc_info['ops']
        
        #insert ops in codebytes (field with the frequency of each opcode, useful for ML)
        for i in range(0, len(opcodes_list), 2):
            self.data["codebytes"][opcodes_list[i:i+2]] = self.data["codebytes"].get(opcodes_list[i:i+2], 0) +1
        
        call_insns = proc_info['call_insns']
        jump_insns = proc_info['jump_insns']
        flow_insns = []
        for ci in call_insns:
            call_instr = matching.CallInsn(*(ci))
            flow_insns.append(call_instr)
        for ji in jump_insns:
            jump_instr = matching.JumpInsn(*(ji))
            flow_insns.append(jump_instr) 

        handler = matching.ProcedureHandler(fcn_bytes, insns_list, proc_info["offset"], flow_insns, self.arch)
        handler.handleFlow()
        handler.lift()

        proc_dict = {
            "offset": proc_info["offset"],
            "proc_desc": {
                "name": proc_info["name"],
                "raw": proc_info['raw_data'],
                "asm": proc_info['asm'],
                "callconv": proc_info["callconv"],
                "apicalls": handler.api,
                "arch": self.arch.name
            }
        }
        
        proc_dict["proc_desc"]["flow_hash"] = handler.flowhash.encode("hex")
        proc_dict["proc_desc"]["vex_hash"] = handler.vexhash.encode("hex")
        proc_dict["proc_desc"]["full_hash"] = hashlib.md5(fcn_bytes).hexdigest()
        
        return proc_dict   



