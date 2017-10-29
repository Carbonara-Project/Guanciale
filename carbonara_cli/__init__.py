#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, willownoises@gmail.com"

import json
import base64
import hashlib
import binascii
import struct
import os
import r2handler
import idblib
import capstone
import progressbar
import idb
import config
import matching
import pyvex

class BinaryInfo(object):
    def __init__(self, filename):
        '''
        BinaryInfo

        :param str filename: The filename of target binary
        '''

        print "[Retrieving basic info about binary]"
        #open the binary file and compute sha256 hash
        binfile = open(filename, "rb")
        hash_object = hashlib.md5(binfile.read())
        hex_dig = hash_object.hexdigest()
        
        self.data = {
            "program": {
                "md5": hex_dig,
                "filename": filename
            },
            "procs": [],
            "codebytes": {}
        }
        
        #open radare2 as subprocess
        self.r2 = r2handler.open(filename)
        
        #r2 cmd iIj : get info about binary in json
        print "1: getting info about file..."
        self.data["info"] = self.r2.cmdj('iIj')
        self.data["info"]["program_class"] = self.data["info"]["class"] #rename for the backend
        del self.data["info"]["class"]
        
        #r2 cmd izzj : get strings contained in the binary in json
        print "2: getting strings list..."
        strings = self.r2.cmdj('izzj')["strings"]
        
        self.data["strings"] = []
        for strg in strings:
            s = {
                "val": strg["string"],
                "offset": strg["paddr"],
                "size": strg["size"],
                "type": strg["type"]
            }
            self.data["strings"].append(s)
        
        #r2 cmd Sj : get sections
        print "3: getting sections..."
        sections = self.r2.cmdj('iSj')
        
        self.data["sections"] = []
        for sec in sections:
            offset = sec["paddr"]
            size = sec["size"]
            
            #calculate md5 of the section
            binfile.seek(offset)
            hash_object = hashlib.md5(binfile.read(size))
            hex_dig = hash_object.hexdigest()
            
            s = {
                "name": sec["name"],
                "offset": offset,
                "size": size,
                "md5": hex_dig
            }
            self.data["sections"].append(s)
        
        binfile.close()
        
        print "4: calculating entropy..."
        self.data["entropy"] = self.r2.cmdj('p=ej') #TODO ??? must be rewritten!!! listen ML experts

    def __del__(self):
        if "r2" in self.__dict__:
            self.r2.quit()

    def addProc(self, name, asm, raw, ops, offset, callconv, flow):
        '''
        generate a dictionary with the informations needed to describe a procedure and add it to the procedures list

        :param str name: The procedure name
        :param str asm: The disassembly with comments
        :param str raw: The bytes of the function
        :param str ops: List of first bytes of each instruction
        :param integer offset: The offset of function from the binary base address
        :param str callconv: The calling canvention of the procedure
        :param array<JumpInsn> flow: Array of jump (or call) object extracted from the code
        '''
        
        ''' "+++++++++ %s +++++++++" % name
        print asm
        print'''
        
        handler = matching.ProcedureHandler(raw, offset, flow, matching.archFromR2("x86",64,"little"))
        
        handler.handleFlow()
        
        handler.lift()
        
        '''print "+++++++++++++++++++++++++"
        print'''
        
        proc = {
            "name": name,
            "raw": base64.b64encode(raw),
            "asm": asm,
            "offset": offset,
            "callconv": callconv,
            "apicalls": handler.api
        }
        hash_object = hashlib.md5("PIPPO")
        proc["hash1"] = handler.api_hash.encode("hex")
        proc["hash2"] = handler.internals_hash.encode("hex")
        proc["hash3"] = handler.jumps_flow_hash.encode("hex")
        proc["hash4"] = handler.flow_hash.encode("hex")
        proc["hash5"] = handler.consts_hash.encode("hex")
        proc["hash6"] = handler.vex_code_hash.encode("hex")
        proc["hash7"] = hashlib.md5(str(ops)).digest().encode("hex")
        proc["full_hash"] = hashlib.md5(raw).hexdigest()
        self.data["procs"].append(proc)

    def addString(self, string):
        self.data["strings"].append(string)

    def toJson(self):
        #return str(self.data)
        return json.dumps(self.data, indent=2, ensure_ascii=True)

    def __str__(self):
        return self.toJson()

    def fromIdaDB(self, filename):
        pass #TODO call ida and parse idb with idapython

    def _r2Task(self):
        '''
        Get info from the radare2 process
        '''

        #r2 cmd ilj : get imported libs in json
        print "2: getting imported libraries..."
        self.data["libs"] = self.r2.cmdj('ilj')
        
        #r2 cmd ilj : get imported functions in json
        print "3: getting imported procedures names..."
        imports = self.r2.cmdj('iij')
        
        self.data["imports"] = []
        for imp in imports:
            i = {
                "name": imp["name"],
                "addr": imp["plt"] #??? for PE binaries?
            }
            self.data["imports"].append(i)
        
        #r2 cmd ilj : get exported symbols in json
        print "4: getting exported symbols..."
        exports = self.r2.cmdj('iEj')
        
        self.data["exports"] = []
        for exp in exports:
            e = {
                "name": exp["name"],
                "offset": exp["paddr"],
                "size": exp["size"]
            }
            self.data["exports"].append(e)

        #r2 cmd aflj : get info about analyzed functions
        print "5: getting list of analyzed procedures..."
        funcs_dict = self.r2.cmdj('aflj')
        sym_imp_l = len("sym.imp") 
        
        print "6: getting assembly and other info about each procedure..."
        with progressbar.ProgressBar(max_value=len(funcs_dict)) as bar:
            count = 0
            for func in funcs_dict:
                #skip library symbols
                if len(func["name"]) >= sym_imp_l and func["name"][:sym_imp_l] == "sym.imp":
                    continue
                
                fcn_offset = func["offset"]
                fcn_size = func["size"]
                fcn_name = func["name"]
                fcn_call_conv = func["calltype"]
                
                #r2 cmd pdfj : get assembly from a function in json
                fcn_instructions = self.r2.cmdj('pdfj @ ' + fcn_name)
                
                #r2 cmd p6e : get bytes of a function in base64
                self.r2.cmd('s ' + str(fcn_offset))
                fcn_bytes = base64.b64decode(self.r2.cmd('p6e ' + str(fcn_size)).rstrip())
                
                asm = ""
                opcodes_list = ""
                
                flow_insns = []
                
                for instr in fcn_instructions["ops"]:
                    if instr["type"] == "invalid":
                        continue
                    
                    #get the first byte in hex
                    first_byte = instr["bytes"][:2]
                    opcodes_list += first_byte
                    
                    #insert ops in codebytes (field with the frequency of each opcode, useful for ML)
                    self.data["codebytes"][first_byte] = self.data["codebytes"].get(first_byte, 0) +1
                    
                    #insert comments in disassembly if presents
                    if "comment" in instr:
                        asm += instr["opcode"] + "  ; " + base64.b64decode(instr["comment"]) + "\n"
                    else:
                        asm += instr["opcode"] + "\n"
                        
                    #check if the instruction is of type 'call'
                    #TODO!!! skip call and jumps to registers
                    if instr["type"] == "call":
                        target_name = instr["opcode"].split()[-1]
                        call_instr = None
                        if target_name[:sym_imp_l] == "sym.imp":
                            call_instr = matching.CallInsn(instr["offset"], instr["size"], instr["jump"], target_name[sym_imp_l +1:], True)
                        elif target_name[:len("sub.")] == "sub.":
                            call_instr = matching.CallInsn(instr["offset"], instr["size"], instr["jump"], target_name[len("sub."):], True)
                        else:
                            call_instr = matching.CallInsn(instr["offset"], instr["size"], instr["jump"], target_name)
                        flow_insns.append(call_instr)
                    #check if the instruction is of type 'jump'
                    elif instr["type"] == "cjmp" or instr["type"] == "jmp":
                        target = instr["jump"]
                        jumpout = target < fcn_offset or target >= fcn_offset + fcn_size
                        jump_instr = matching.JumpInsn(instr["offset"], instr["size"], target, jumpout)
                        flow_insns.append(jump_instr)
                
                self.addProc(fcn_name, asm, fcn_bytes, opcodes_list.decode("hex"), fcn_offset, fcn_call_conv, flow_insns)
                count += 1
                bar.update(count)

    def fromR2Project(self, name):
        '''
        Get information about binary stored in a radare2 project

        :param str name: The name of the radare2 project or its path
        '''

        print "[Retrieving info from radare2 project]"
        
        #set project directory var in radare
        projdir = os.path.dirname(name)
        projname = os.path.basename(name)
        if projdir != "":
            projdir = os.path.expanduser(projdir)
            self.r2.cmd("e dir.projects=" + projdir)
        
        #r2 cmd Po : load project
        print "1: loading project..."
        out = self.r2.cmd("Po " + projname)
        if len(out) >= len("Cannot open project info") and out == "Cannot open project info":
            raise RuntimeError("cannot load radare2 project " + name)
        
        self._r2Task()

    def generateInfo(self):
        '''
        Grab basic informations about the binary from r2
        '''

        print "[Retrieving info about procedures]"
        
        #r2 cmd aa : analyze all
        print "1: analyzing all..."
        self.r2.cmd("aaa")
        
        self._r2Task()


def main():
    import sys
    import time
    import zlib

    if len(sys.argv) < 2 or sys.argv[1] == "-help":
        print "usage: python carbonara-cli.py [OPTIONS] <binary file>"
        print
        exit(0)

    args = {}
    binary = None
    hasdb = False

    config.populate()

    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "-r2proj":
            if i == len(sys.argv) -1:
                print "error: arg '-r2proj': expected one argument"
                print "ABORT"
                exit(1)
            if hasdb:
                print "error: arg '%s': disassembly database specified yet, ignored" % sys.argv[i+1]
                continue
            args["r2"] = sys.argv[i+1]
            hasdb = True
            i += 1
        elif sys.argv[i] == "-idb":
            if i == len(sys.argv) -1:
                print "error: arg '-idb': expected one argument"
                print "ABORT"
                exit(1)
            if hasdb:
                print "error: arg '%s': disassembly database specified yet, ignored" % sys.argv[i+1]
                continue
            hasdb = True
            args["idb"] = sys.argv[i+1]
            i += 1
        elif sys.argv[i] == "-idacmd":
            if i == len(sys.argv) -1:
                print "error: arg '-idacmd': expected one argument"
                print "ABORT"
                exit(1)
            config.idacmd = sys.argv[i+1]
            i += 1
        elif sys.argv[i] == "-ida64cmd":
            if i == len(sys.argv) -1:
                print "error: arg '-ida64cmd': expected one argument"
                print "ABORT"
                exit(1)
            config.ida64cmd = sys.argv[i+1]
            i += 1
        elif sys.argv[i] == "-radare2":
            if i == len(sys.argv) -1:
                print "error: arg '-radare2': expected one argument"
                print "ABORT"
                exit(1)
            config.radare2 = sys.argv[i+1]
            i += 1
        elif sys.argv[i] == "-reconfig":
            config.generateConfig()
        elif sys.argv[i] == "-writeconfig":
            print "Y"
            config.writeConfig()
        elif binary == None:
            binary = sys.argv[i]
        elif hasdb:
            print "error: arg '%s': disassembly database specified yet, ignored" % sys.argv[i]
        else:
            dbfile = sys.argv[i]
            ext = os.path.splitext(dbfile)[-1]
            if ext == "idb" or ext == "i64":
                args["idb"] = dbfile
            else:
                print "message: no project type info, Radare2 assumed"
                args["r2"] = dbfile
        i += 1

    if binary == None:
        print "error: binary file not provided"
        print "ABORT"
        exit(1)

    start_time = time.time()

    try:
        bi = BinaryInfo(binary)
    except IOError as err:
        print "error: %s" % err
        print "ABORT"
        exit(1)
    if "idb" in args:
        bi.fromIdb(args["idb"])
    elif "r2" in args:
        bi.fromR2Project(args["r2"])
    else:
        bi.generateInfo()
    data = bi.toJson()

    outfile = open(sys.argv[1] + ".analisys.json", "w")
    outfile.write(data)
    outfile.close()
    outfile = open(sys.argv[1] + ".analisys.json.gz", "w")
    outfile.write(zlib.compress(data))
    outfile.close()

    print
    print "elapsed time: " + str(time.time() - start_time)



