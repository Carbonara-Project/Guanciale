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
import status
import idb
import config
import matching
import subprocess

class ArchNotSupported(RuntimeError):
    pass

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
        
        #r2 cmd izzj : get strings contained in the binary in json
        print "1: getting strings list..."
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
        print "2: getting sections..."
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
        
        print "3: calculating entropy..."
        self.data["entropy"] = self.r2.cmdj('p=ej') #TODO ??? must be rewritten!!! listen ML experts

    def __del__(self):
        if "r2" in self.__dict__:
            self.r2.quit()

    def addProc(self, name, asm, raw, insns_list, ops, offset, callconv, flow):
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
        
        handler = matching.ProcedureHandler(raw, insns_list, offset, flow, self.arch)
        
        handler.handleFlow()
        
        handler.lift()
        
        proc = {
            "name": name,
            "raw": base64.b64encode(raw),
            "asm": asm,
            "offset": offset,
            "callconv": callconv,
            "apicalls": handler.api
        }

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
        '''
        Get information about binary stored in a IDA database

        :param str filename: The name of the IDA databse or its path
        '''
        
        if config.idacmd == None:
             raise NotImplementedError() #parse idb without calling IDA

        print "2: Waiting for IDA to parse database (this may take several minutes)..."
        file_ext = os.path.splitext(filename)[1]
        if file_ext == '.idb':
            process = subprocess.Popen(config.idacmd + ' -A -S"' + os.path.join(os.path.dirname(__file__), "idascript.py") + '" ' + filename)
        elif file_ext == '.i64':
            process = subprocess.Popen(config.ida64cmd + ' -A -S"' + os.path.join(os.path.dirname(__file__), "idascript.py") + '" ' + filename)
        else:
            raise RuntimeError('file not supported')
        process.wait()

        #getting data from idascript via json
        idadump = open('dump.json', 'r')
        data = json.load(idadump)
        idadump.close()

        #clean up
        os.remove('dump.json')
        
        print "2: getting file properties..."
        self.data['info'] = data['info']

        try:
            self.arch = matching.archFromIda(self.data["info"]["arch"], self.data["info"]["bits"], self.data["info"]["endian"])
        except:
            raise ArchNotSupported("arch %s not supported" % self.data["info"]["arch"])
        self.data["info"]["arch"] = self.arch.name
        
        print "3: getting imported libraries..."
        self.data['libs'] = data['libs']

        print "4: getting imported procedures names..."
        self.data['imports'] = data['imports']

        print "5: getting exported symbols..."
        self.data["exports"] = data['exports']

        print "6: getting assembly and other info about each procedure..."
        
        with status.Status(len(data['procedures'])) as bar:
            count = 0
            for func in data['procedures']:
                try:
                    fcn_name = func['name']
                    asm = func['asm']
                    fcn_bytes = base64.b64decode(func['raw_data'])
                    insns_list = []
                    for ins in func['insns_list']:
                        insns_list.append(base64.b64decode(ins))
                    opcodes_list = func['ops']
                    fcn_offset = func['offset']
                    fcn_call_conv = func['callconv']
                    _flow_insns = func['flow_insns']
                    flow_insns = []
                    for fi in _flow_insns:
                        if fi[0] == 0:
                            call_instr = matching.CallInsn(*(fi[1:]))
                            flow_insns.append(call_instr)
                        elif fi[0] == 1:
                            jump_instr = matching.JumpInsn(*(fi[1:]))
                            flow_insns.append(jump_instr)               
                    self.addProc(fcn_name, asm, fcn_bytes, insns_list, opcodes_list.decode("hex"), fcn_offset, fcn_call_conv, flow_insns)
                except Exception as err:
                    print "error on function %s, skipped" % func["name"]
                count += 1
                bar.update(count)

        

    def _r2Task(self):
        '''
        Get info from the radare2 process
        '''

        #r2 cmd iIj : get info about binary in json
        print "2: getting file properties..."
        self.data["info"] = self.r2.cmdj('iIj')
        self.data["info"]["program_class"] = self.data["info"]["class"] #rename for the backend
        del self.data["info"]["class"]
        
        try:
            self.arch = matching.archFromR2(self.data["info"]["arch"], self.data["info"]["bits"], self.data["info"]["endian"])
        except:
            raise ArchNotSupported("arch %s not supported" % self.data["info"]["arch"])
        self.data["info"]["arch"] = self.arch.name
        
        #r2 cmd ilj : get imported libs in json
        print "3: getting imported libraries..."
        self.data["libs"] = self.r2.cmdj('ilj')
        
        #r2 cmd ilj : get imported functions in json
        print "4: getting imported procedures names..."
        imports = self.r2.cmdj('iij')
        
        self.data["imports"] = []
        for imp in imports:
            i = {
                "name": imp["name"],
                "addr": imp["plt"] #??? for PE binaries?
            }
            self.data["imports"].append(i)
        
        #r2 cmd ilj : get exported symbols in json
        print "5: getting exported symbols..."
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
        print "6: getting list of analyzed procedures..."
        funcs_dict = self.r2.cmdj('aflj')
        sym_imp_l = len("sym.imp") 
        
        print "7: getting assembly and other info about each procedure..."
        with status.Status(len(funcs_dict)) as bar:
            count = 0
            for func in funcs_dict:
                try:
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
                    
                    insns_list = []
                    asm = ""
                    opcodes_list = ""
                    
                    flow_insns = []
                    
                    for instr in fcn_instructions["ops"]:
                        if instr["type"] == "invalid":
                            break
                        
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
                        if instr["type"] == "call" and "jump" in instr:
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
                        elif (instr["type"] == "cjmp" or instr["type"] == "jmp") and "jump" in instr:
                            target = instr["jump"]
                            jumpout = target < fcn_offset or target >= (fcn_offset + fcn_size)
                            jump_instr = matching.JumpInsn(instr["offset"], instr["size"], target, jumpout)
                            flow_insns.append(jump_instr)
                        
                        insns_list.append(instr["bytes"].decode("hex"))
                    
                    self.addProc(fcn_name, asm, fcn_bytes, insns_list, opcodes_list.decode("hex"), fcn_offset, fcn_call_conv, flow_insns)
                except Exception as err:
                    print "error on function %s, skipped" % func["name"]
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

        print "[Extracting info from binary]"
        
        #r2 cmd aa : analyze all
        print "1: analyzing all..."
        self.r2.cmd("aaa")
        
        self._r2Task()



