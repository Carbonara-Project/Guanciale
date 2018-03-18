#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, rop2bash@gmail.com"

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
import struct
import time
import datasketch
import multiprocessing as mp
from errors import *

_DEBUG = True if "DEBUG" in os.environ else False
_WINDOWS = True if os.name == "nt" else False

RED=''if _WINDOWS else '\033[0;31m'
GREEN=''if _WINDOWS else '\033[0;32m'
LCYAN=''if _WINDOWS else '\033[0;96m'
LMAG=''if _WINDOWS else '\033[95m'
NC=''if _WINDOWS else '\033[0m'
LMAG_BG=''if _WINDOWS else '\033[105m'
RED_BG=''if _WINDOWS else '\033[41m'
YELL_BG=''if _WINDOWS else '\033[43m'

def printerr(s):
    sys.stderr.write(RED_BG + "  error  " + NC + " " + str(s) + "\n")

def printwarn(s):
    sys.stderr.write(YELL_BG + " warning " + NC + " " + str(s) + "\n")


def printout(s):
    sys.stdout.write(s)
    sys.stdout.flush()

_MODE_R2 = 0
_MODE_IDA = 1
_MODE_IDB = 2

R2PLUGIN = 0xABADCAFE


def _processR2Procedure(proc_info, imports_dict, arch):
    try:
        insns_list = []
        asm = ""
        flow_insns = []
        
        fcn_offset = proc_info["offset"]
        fcn_size = proc_info["size"]
        sym_imp_l = len("sym.imp") 
        
        for instr in proc_info["instructions"]:
            if instr["type"] == "invalid":
                continue
            
            #get the first byte in hex
            first_byte = instr["bytes"][:2]

            #insert ops in codebytes (field with the frequency of each opcode, useful for ML)
            #self.data["codebytes"][first_byte] = self.data["codebytes"].get(first_byte, 0) +1
            
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
                #elif target_name[:len("sub.")] == "sub.":
                #    call_instr = matching.CallInsn(instr["offset"], instr["size"], instr["jump"], target_name[len("sub."):], True)
                elif target_name[:len("sym.")] == "sym." and target_name[len("sym."):] in imports_dict:
                    call_instr = matching.CallInsn(instr["offset"], instr["size"], instr["jump"], target_name[len("sym."):], True)
                elif target_name in imports_dict:
                    call_instr = matching.CallInsn(instr["offset"], instr["size"], instr["jump"], target_name, True)
                else:
                    call_instr = matching.CallInsn(instr["offset"], instr["size"], instr["jump"], target_name)
                flow_insns.append(call_instr)
                
            #check if the instruction is of type 'jump'
            elif (instr["type"] == "cjmp" or instr["type"] == "jmp") and "jump" in instr:
                target = instr["jump"]
                jumpout = target < fcn_offset or target >= (fcn_offset + fcn_size)
                jump_instr = matching.JumpInsn(instr["offset"], instr["size"], target, jumpout)
                flow_insns.append(jump_instr)
            
            insns_list.append((instr["offset"], instr["bytes"].decode("hex")))
        
        handler = matching.ProcedureHandler(insns_list, flow_insns, arch)
        handler.work()
        
        '''
        print
        print "****** (0x%x) %s ******" % (fcn_offset, proc_info["name"])
        print asm
        print
        print handler.vex_code
        print
        print handler.shingled_code
        print
        '''
        
        proc_dict = {
            "offset": fcn_offset,
            "proc_desc": {
                "name": proc_info["name"],
                "raw": base64.b64encode(proc_info["bytes"]),
                "raw_len": len(proc_info["bytes"]),
                "asm": asm,
                "callconv": proc_info["calltype"],
                "apicalls": handler.api,
                "arch": arch.name
            }
        }
        
        proc_dict["proc_desc"]["flow_hash"] = handler.flowhash.encode("hex")
        proc_dict["proc_desc"]["vex_hash"] = handler.vexhash.encode("hex")
        
        return proc_dict
    except Exception:
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return proc["name"]

def _processIDAProcedure(proc_info, imports_dict, arch):
    try:
        fcn_bytes = base64.b64decode(proc_info['raw_data'])
        insns_list = []
        for ins in proc_info['insns_list']:
            insns_list.append((ins[0], base64.b64decode(ins[1])))
        opcodes_list = proc_info['ops']
        
        #insert ops in codebytes (field with the frequency of each opcode, useful for ML)
        #for i in range(0, len(opcodes_list), 2):
        #    self.data["codebytes"][opcodes_list[i:i+2]] = self.data["codebytes"].get(opcodes_list[i:i+2], 0) +1
        
        flow_insns_tuples = proc_info['flow_insns']
        flow_insns = []
        for ins in flow_insns_tuples:
            if len(ins) == 5:
                instr = matching.CallInsn(*(ins))
            elif len(ins) == 4:
                instr = matching.JumpInsn(*(ins))
            flow_insns.append(instr) 

        handler = matching.ProcedureHandler(insns_list, flow_insns, arch)
        handler.work()
        
        if proc_info["callconv"] == "":
            proc_info["callconv"] = None
        
        proc_dict = {
            "offset": proc_info["offset"],
            "proc_desc": {
                "name": proc_info["name"],
                "raw": proc_info['raw_data'],
                "raw_len": len(fcn_bytes),
                "asm": proc_info['asm'],
                "callconv": proc_info["callconv"],
                "apicalls": handler.api,
                "arch": arch.name
            }
        }
        
        proc_dict["proc_desc"]["flow_hash"] = handler.flowhash.encode("hex")
        proc_dict["proc_desc"]["vex_hash"] = handler.vexhash.encode("hex")
        
        return proc_dict
    except Exception:
        if _DEBUG:
            import traceback
            traceback.print_exc()
        return proc["name"]


class BinaryInfo(object):

    def _cmd_j(self, cmd):
        o = self.r2.cmd(cmd)
        try:
            r = json.loads(o)
        except:
            return None
        return r

    def __init__(self, filename, arch=None, bits=None):
        
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
        
        if arch != None:
            if arch not in ("arm", "x86", "mips", "ppc"):
                raise ValueError("BinaryInfo: arch_bits_endian param: arch %s not supported" % str(arch))
            self.r2.cmd("e asm.arch=%s" % arch)
        
        if bits != None:
            try:
                bits = int(bits)
            except:
                raise ValueError("BinaryInfo: arch_bits_endian param: bits %s not supported" % str(bits))
            if bits not in (32, 64):
                raise ValueError("BinaryInfo: arch_bits_endian param: bits %s not supported" % str(bits))
            self.r2.cmd("e asm.bits=%d" % bits)
            
        #open the binary file and compute md5 and sha256 hash
        printout(RED + "[ ]" + NC + "  Computing hashes of the entire binary")
        binfile = open(filename, "rb")
        self.content = binfile.read()
        
        hash_object = hashlib.md5(self.content)
        md5_dig = hash_object.hexdigest()
        hash_object = hashlib.sha256(self.content)
        sha256_dig = hash_object.hexdigest()
        
        binfile.close()
        printout("\r" + GREEN + "[x]" + NC + " Computing hashes of the entire binary \n")
        
        print(" >> md5: " + md5_dig)
        print(" >> sha256: " + sha256_dig)
        
        self.md5 = md5_dig
        
        self.data = {
            "program": {
                "md5": md5_dig,
                "sha256": sha256_dig
            },
            "procs": [],
            #"codebytes": {}
        }
        
        #get binary properties
        printout(RED + "[ ]" + NC + " Getting basic properties from the binary")
        self.data["info"] = self._cmd_j('iIj')
        self.data["info"]["program_class"] = self.data["info"]["class"] #rename for the backend
        del self.data["info"]["class"]
        
        if arch != None:
            self.data["info"]["arch"] = arch
        if bits != None:
            self.data["info"]["bits"] = bits
        
        self.data["info"]["filename"] = filename
        self.filename = filename
        printout("\r" + GREEN + "[x]" + NC + " Getting basic properties from the binary\n")
    
    def __del__(self):
        try:
            if hasattr(self, "r2"):
                self.r2.quit()
        except: pass
    
    
    def addAdditionalInfo(self):
        #calculate entropy
        printout(RED + "[ ]" + NC + " Calculating entropy")
        r2_entropy = self._cmd_j('p=ej 1')
        self.data["info"]["entropy"] = r2_entropy["entropy"][0]["value"]
        printout("\r" + GREEN + "[x]" + NC + " Calculating entropy\n")
        
        #get sections
        printout(RED + "[ ]" + NC + " Extracting info about sections")
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
        printout("\r" + GREEN + "[x]" + NC + " Extracting info about sections\n")
        
        
    def addStrings(self):
        #get strings contained in the binary
        '''
        printout(RED + "[ ]" + NC + " Getting strings")
        r2_strings = self._cmd_j('izzj')["strings"]
        
        N = 4
        strhash = datasketch.MinHash(num_perm=256)
        for strg in r2_strings:
            val = base64.b64decode(strg["string"])
            if len(val) < 4:
                strhash.update(val)
                continue
            
            for i in xrange(len(sentence)-N+1):
                strhash.update(val[i:i+N])
        
        lean_strhash = datasketch.LeanMinHash(strhash)
        strhash_buf = bytearray(lean_strhash.bytesize())
        lean_strhash.serialize(strhash_buf)
        self.data["str_hash"] = str(strhash_buf).encode("hex")
        
        printout("\r" + GREEN + "[x]" + NC + " Getting strings\n")
        '''
        #printout(RED + "[ ]" + NC + " Getting strings")
        #r2_strings = self._cmd_j('izzj')["strings"]
        
        self.data["strings"] = []
        '''for strg in r2_strings:
            s = {
                "val": strg["string"],
                "offset": strg["paddr"],
                "size": strg["size"],
                "encoding": strg["type"]
            }
            self.data["strings"].append(s)'''
        #printout("\r" + GREEN + "[x]" + NC + " Getting strings\n")
    
    
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
            processProc = _processR2Procedure
        elif self._mode == _MODE_IDA:
            self.processProc = self._processIDAProcedure
        elif self._mode == _MODE_IDB:
            self.processProc = self._processR2Procedure
        else:
            raise RuntimeError("BinaryInfo.processSingle: mode not valid")
        
        printout(RED + "[ ]" + NC + " Searching target procedure")
        for proc in self.procs:
            if proc["name"] == proc_search or hex(proc["offset"]) == proc_search or str(proc["offset"]) == proc_search:
                printout("\r" + GREEN + "[x]" + NC + " Searching target procedure\n")
                printout(RED + "[ ]" + NC + " Processing target procedure")
                data = {
                    "program": self.md5,
                    "procedure": self.processProc(proc)
                }
                printout("\r" + GREEN + "[x]" + NC + " Processing target procedure\n")
                return data
        printout("\r" + GREEN + "[x]" + NC + " Searching target procedure\n")
        return None
    
    
    def processAll(self, workers=None):
        
        if self._mode == _MODE_R2:
            processProc = _processR2Procedure
            imports_dict = self.imports_dict
        elif self._mode == _MODE_IDA:
            processProc = _processIDAProcedure
            imports_dict = None
        elif self._mode == _MODE_IDB:
            processProc = _processR2Procedure
            imports_dict = self.imports_dict
        else:
            raise RuntimeError("BinaryInfo.processAll: mode not valid")
        
        results = []
        
        
        print(" >> Processing all procedures")
        with status.Status(len(self.procs)) as bar:
            
            def _callback(res):
                if type(res) == type(""):
                    printerr(" >> " + RED + "Error" + NC +" on function %s, skipped" % res)
                else:
                    results.append(res)
                bar.update(len(results))
            
            if workers == 1:
                count = 0
                for proc in self.procs:
                    r = processProc(proc, imports_dict, self.arch)
                    _callback(r)
                    count += 1
                    bar.update(count)
            else:
                if workers == None:
                    pool = mp.Pool(mp.cpu_count())
                else:
                    pool = mp.Pool(workers)
                
                r = [pool.apply_async(processProc, args=(proc, imports_dict, self.arch), callback=_callback) for proc in self.procs]
                pool.close()
                
                pool.join()
        
        self.data["procs"] = results
        
        return self.data
    


    def _generateR2(self):
        #analyze all
        printout(RED + "[ ]" + NC + " Analyzing all")
        self.r2.cmd("aaa")
        printout(GREEN + "[x]" + NC + " Analyzing all\n")
        self._grabR2Procedures()
    
    
    def _fromR2Project(self, filename):
        printout(RED + "[ ]" + NC + " Loading radare project")
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
        printout("\r" + GREEN + "[x]" + NC + " Loading radare project\n")
        
        self._grabR2Procedures()
    
    
    def _grabR2Procedures(self):
        #map architecture
        try:
            self.arch = matching.archFromR2(self.data["info"]["arch"], self.data["info"]["bits"], self.data["info"]["endian"])
        except:
            raise ArchNotSupported("arch %s (%d bits) not supported" % (self.data["info"]["arch"], self.data["info"]["bits"]))
        self.data["info"]["arch"] = self.arch.name
        
        printout(RED + "[ ]" + NC + " Getting linked libraries")
        libs_list = self._cmd_j('ilj')
        self.data['libs'] = []
        if libs_list == None:
            libs_list = []
        for lib in libs_list:
            self.data['libs'].append({"name": lib})
        printout("\r" + GREEN + "[x]" + NC + " Getting linked libraries\n")
        
        printout(RED + "[ ]" + NC + " Getting imported functions")
        #get imported functions
        imports = self._cmd_j('iij')
        
        self.data["imports"] = []
        self.imports_dict = {}
        for imp in imports:
            if len(imp["name"]) == 0:
                continue
            
            i = {
                "name": imp["name"],
                "addr": imp["plt"] #??? for PE binaries?
            }
            for lib in libs_list:
                if len(imp["name"]) > len(lib) and imp["name"][:len(lib)] == lib:
                    self.imports_dict[imp["name"][len(lib):]] = imp["plt"]
                    break
            
            self.data["imports"].append(i)
        printout("\r" + GREEN + "[x]" + NC + " Getting imported functions\n")
        
        printout(RED + "[ ]" + NC + " Getting exported symbols")
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
        printout("\r" + GREEN + "[x]" + NC + " Getting exported symbols\n")
        
        #get analyzed funtions list
        printout(RED + "[ ]" + NC + " Getting procedures list")
        funcs_dict = self._cmd_j('aflj')
        printout("\r" + GREEN + "[x]" + NC + " Getting procedures list\n")
        
        if hasattr(self, "r2plugin"):
            if funcs_dict == None:
                print(" >> Procedure list is empty, performing an analysis with 'aaa'")
                #analyze all
                printout(RED + "[ ]" + NC + " Analyzing all")
                self.r2.cmd("aaa")
                printout(GREEN + "[x]" + NC + " Analyzing all\n")
                printout(RED + "[ ]" + NC + " Getting procedures list (again)")
                funcs_dict = self._cmd_j('aflj')
                printout("\r" + GREEN + "[x]" + NC + " Getting procedures list (again)\n")
        
        if funcs_dict == None:
            raise RuntimeError("BinaryInfo._grabR2Procedures: cannot get list of procedures")
        
        sym_imp_l = len("sym.imp")
        
        printout(RED + "[ ]" + NC + " Building procedures index (0/%d)" % len(funcs_dict))
        
        self.procs = []
        #self.procs_names = {}
        #self.procs_addrs = {}
        
        i = 1
        for func in funcs_dict:
            printout("\r" + RED + "[ ]" + NC + " Building procedures index (%d/%d)" % (i, len(funcs_dict)))
            try:
                #skip library symbols
                if len(func["name"]) >= sym_imp_l and func["name"][:sym_imp_l] == "sym.imp":
                    i += 1
                    continue
                
                self.r2.cmd("s " + hex(func["offset"]))
                
                #get assembly from a function 
                fcn_instructions = self._cmd_j('pdrj')
                if fcn_instructions == None:
                    o = self.r2.cmd('pdrj')
                    if o.endswith("},]"): #fix for strange radare bug
                        fcn_instructions = json.loads(o[:-2] + "]")
                
                #r2 cmd p6e : get bytes of a function in base64
                fcn_bytes = base64.b64decode(self.r2.cmd('p6e ' + str(func["size"])).rstrip())
                
                #self.procs_names[func["name"]] = len(self.procs)
                #self.procs_addrs[func["offset"]] = len(self.procs)
                
                self.procs.append({
                    "offset": func["offset"],
                    "name": func["name"],
                    "size": func["size"],
                    "calltype": func["calltype"],
                    "instructions": fcn_instructions,
                    "bytes": fcn_bytes
                })
            except Exception:
                if _DEBUG:
                    import traceback
                    traceback.print_exc()
                printerr(" >> " + RED + "Error" + NC +" on function %s, skipped" % func["name"])
            i += 1
        printout("\r" + GREEN + "[x]" + NC + " Building procedures index\n")
    
    



    def _fromIDAPro(self, filename):
        printout(RED + "[ ]" + NC + " Waiting for IDA to parse database (this may take several minutes)...")
        
        binname = os.path.splitext(filename)[0]
        rand = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
        dumpname = '.'+binname+ '-'+ rand +'-dump.json'

        file_ext = os.path.splitext(filename)[1]
        idascript = os.path.join(os.path.dirname(os.path.abspath(__file__)), "idascript.py ")
        
        if config.usewine:
            idascript.replace(os.path.sep, "\\")
        
        if file_ext == '.idb':
            if config.usewine:
                process = subprocess.Popen(config.idacmd + ' -A -S"' + idascript + dumpname +'" "' + filename + '"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                process = subprocess.Popen(config.idacmd + ' -A -S"' + idascript + dumpname +'" "' + filename + '"')
        elif file_ext == '.i64':
            if config.usewine:
                process = subprocess.Popen(config.ida64cmd + ' -A -S"' + idascript + dumpname +'" "' + filename + '"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                process = subprocess.Popen(config.ida64cmd + ' -A -S"' + idascript + dumpname +'" "' + filename + '"')
        else:
            raise RuntimeError('BinaryInfo._fromIDAPro: extension %s is not supported' % file_ext)
        process.wait()
        
        #getting data from idascript via json
        try:
            idadump = open(dumpname, 'r')
            data = json.load(idadump)
            idadump.close()
        except IOError:
            raise RuntimeError("BinaryInfo._fromIDAPro: cannot retrieve data from IDA Pro, problably you have another instance of IDA working on the database")
            
        #clean up
        os.remove(dumpname)
        printout("\r" + GREEN + "[x]" + NC + " Waiting for IDA to parse database (this may take several minutes)...\n")
                
        printout(RED + "[ ]" + NC + " Getting file properties and symbols")
        #self.data['info'] = data['info']
        for key in data['info']:
            self.data['info'][key] = data['info'][key]
        
        try:
            self.arch = matching.archFromIda(self.data["info"]["arch"], self.data["info"]["bits"], self.data["info"]["endian"])
        except:
            raise ArchNotSupported("arch %s (%d bits) not supported" % (self.data["info"]["arch"], self.data["info"]["bits"]))
        self.data["info"]["arch"] = self.arch.name
        
        self.data['libs'] = data['libs']

        self.data['imports'] = data['imports']

        self.data["exports"] = data['exports']
        printout("\r" + GREEN + "[x]" + NC + " Getting file properties and symbols\n")
        
        self.procs = data['procedures']


    def _parseIDB(self, filename):
        import logging
        import carbonara_idb as idb
        import idblib
        
        logging.basicConfig()
        
        printout(RED + "[ ]" + NC + " Getting linked libraries")
        libs_list = self._cmd_j('ilj')
        self.data['libs'] = []
        for lib in libs_list:
            self.data['libs'].append({"name": lib})
        printout("\r" + GREEN + "[x]" + NC + " Getting linked libraries\n")
        
        printout(RED + "[ ]" + NC + " Getting imported functions")
        #get imported functions
        imports = self._cmd_j('iij')
        
        self.data["imports"] = []
        self.imports_dict = {}
        for imp in imports:
            if len(imp["name"]) == 0:
                continue
            
            i = {
                "name": imp["name"],
                "addr": imp["plt"] #??? for PE binaries?
            }
            for lib in libs_list:
                if len(imp["name"]) > len(lib) and imp["name"][:len(lib)] == lib:
                    self.imports_dict[imp["name"][len(lib):]] = imp["plt"]
                    break
            
            self.data["imports"].append(i)
        printout("\r" + GREEN + "[x]" + NC + " Getting imported functions\n")
        
        printout(RED + "[ ]" + NC + " Getting exported symbols")
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
        printout("\r" + GREEN + "[x]" + NC + " Getting exported symbols\n")
        
        #analyze all
        printout(RED + "[ ]" + NC + " Analyzing all")
        self.r2.cmd("aaa")
        printout(GREEN + "[x]" + NC + " Analyzing all\n")
        
        def strz(b, o):
            return b[o:b.find(b'\x00', o)].decode('utf-8', 'ignore')
         
        fhandle = open(filename, 'rb')
        idbfile = idblib.IDBFile(fhandle)
        id0 = idblib.ID0File(idbfile, idbfile.getpart(0))

        root = id0.nodeByName('Root Node')
        if root:
            params = id0.bytes(root, 'S', 0x41b994) #whooooo
            if params:
                magic, version, cpu, idpflags, demnames, filetype, coresize, corestart, ostype, apptype = struct.unpack_from("<3sH8sBBH" + (id0.fmt*2)+ "HH", params, 0) #maaagic
                cpu = strz(cpu, 0)[1:]
                #print(magic, version, cpu, idpflags, demnames, filetype, coresize, corestart, ostype, apptype)
        
        try:
            self.arch = matching.archFromIda(cpu, self.data["info"]["bits"], self.data["info"]["endian"])
        except:
            raise ArchNotSupported("arch %s (%d bits) not supported" % (cpu, self.data["info"]["bits"]))
        self.data["info"]["arch"] = self.arch.name
        
        self.procs = []
        
        with idb.from_file(filename) as db:
            api = idb.IDAPython(db)

            ida_funcs = api.idautils.Functions()
            
            sym_imp_l = len("sym.imp")
            
            printout( RED + "[ ]" + NC + " Getting procedures (0/%d)" % len(ida_funcs))
            i = 1
            #iterate for each function
            for func in ida_funcs:
                printout("\r" + RED + "[ ]" + NC + " Getting procedures (%d/%d)" % (i, len(ida_funcs)))
                try:
                    fcn_name = api.idc.GetFunctionName(func)
                    
                    start = api.idc.GetFunctionAttr(func, api.idc.FUNCATTR_START)
                    end = api.idc.GetFunctionAttr(func, api.idc.FUNCATTR_END)

                    cur_addr = start
                    
                    flow_insns = []
                    asm = ''
                    insns_list = []
                    
                    self.r2.cmd('s ' + hex(start))
                    temp_d = self._cmd_j('pdj')
                    if temp_d == None:
                        raise RuntimeError("radare ignored %s" % fcn_name)
                    
                    temp_ins = {}
                    
                    fcn_instructions = []
                    
                    for ins in temp_d:
                        if "offset" in ins:
                            temp_ins[ins["offset"]] = ins
                    
                    #get assembly from function
                    while cur_addr <= end:
                        next_instr = api.idc.NextHead(cur_addr)
                        
                        #get size instr
                        if next_instr > end:
                            size = end - cur_addr
                        else:
                            size = next_instr - cur_addr
                        #print cur_addr
                        flags = api.idc.GetFlags(cur_addr)
                        if api.ida_bytes.isCode(flags):
                            instr = None
                            if cur_addr in temp_ins:
                                instr = temp_ins[cur_addr]
                            else:
                                self.r2.cmd('s ' + hex(cur_addr))
                                temp_d = self._cmd_j('pdj')
                                if temp_d == None:
                                    break
                                for ins in temp_d:
                                    if "offset" in ins:
                                        temp_ins[ins["offset"]] = ins
                                        if ins["offset"] == cur_addr:
                                            instr = ins
                            
                            if instr == None:
                                break
                            #print instr["opcode"]
                            if instr["type"] == "invalid":
                                cur_addr = next_instr
                                continue
                            
                            #get comment if possible
                            try:
                                cmt = api.ida_bytes.get_cmt(cur_addr, True).replace('\n', ' ')
                                instr["comment"] = cmt
                            except:
                                pass
                            
                            fcn_instructions.append(instr)
                            
                        cur_addr = next_instr
                    #get raw bytes from function
                    try:
                        fcn_bytes = api.idc.GetManyBytes(start, end-start)
                    except:
                        self.r2.cmd('s ' + hex(start))
                        #r2 cmd p6e : get bytes of a function in base64
                        fcn_bytes = base64.b64decode(self.r2.cmd('p6e ' + str(end-start)).rstrip())
                    
                    #get callconv => NOT WORKING
                    #flags = api.idc.GetFunctionAttr(func, api.idc.FUNCATTR_FLAGS)
                    #callconv = api.idc.get_optype_flags1(flags)
                    fcn_call_conv = None
                    
                    self.procs.append({
                        "offset": start,
                        "name": fcn_name,
                        "size": end - start,
                        "calltype": fcn_call_conv,
                        "instructions": fcn_instructions,
                        "bytes": fcn_bytes
                    })
                except Exception:
                    if _DEBUG:
                        import traceback
                        traceback.print_exc()
                    printerr(" >> " + RED + "Error" + NC +" on function %s, skipped" % fcn_name)
                i += 1
            printout("\r" + GREEN + "[x]" + NC + " Getting procedures\n")

