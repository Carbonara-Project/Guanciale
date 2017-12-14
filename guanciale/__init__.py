#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, rop2bash@gmail.com"

import json
import base64
import hashlib
import binascii
import struct
import os
import r2handler
import status
import config
import matching
import random
import string
import subprocess

class ArchNotSupported(RuntimeError):
    pass

class BinaryInfo(object):
    def __init__(self, filename):
        """
        BinaryInfo.__init__ open a binary and grab basic iformations
        
        Parameters
        ----------
        self: BinaryInfo
            This instance
        filename: str
            The target binary file
        """

        print("[Retrieving basic info about binary]")
        #open the binary file and compute sha256 hash
        binfile = open(filename, "rb")
        hash_object = hashlib.md5(binfile.read())
        hex_dig = hash_object.hexdigest()
        
        self.data = {
            "program": {
                "md5": hex_dig
            },
            "procs": [],
            "codebytes": {}
        }
        
        #open radare2 as subprocess
        self.r2 = r2handler.open(filename)
        
        #r2 cmd izzj : get strings contained in the binary in json
        print("1: getting strings list...")
        strings = self.r2.cmdj('izzj')["strings"]
        
        self.data["strings"] = []
        for strg in strings:
            s = {
                "val": strg["string"],
                "offset": strg["paddr"],
                "size": strg["size"],
                "encoding": strg["type"]
            }
            self.data["strings"].append(s)
        
        #r2 cmd Sj : get sections
        print("2: getting sections...")
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
        
        print("3: calculating entropy...")
        self.data["entropy"] = self.r2.cmdj('p=ej') #TODO ??? must be rewritten!!! listen ML experts
        self.data["entropy"]["addr_value_list"] = self.data["entropy"]["entropy"]
        del self.data["entropy"]["entropy"]
        
        #r2 cmd iIj : get info about binary in json
        print("4: getting general file properties...")
        self.data["info"] = self.r2.cmdj('iIj')
        self.data["info"]["program_class"] = self.data["info"]["class"] #rename for the backend
        del self.data["info"]["class"]
        
        self.data["info"]["filename"] = filename

        
    def __del__(self):
        if "r2" in self.__dict__:
            self.r2.quit()

    def addProc(self, name, asm, raw, insns_list, ops, offset, callconv, flow):
        """
        BinaryInfo.addProc generate a dictionary with the informations needed to describe a procedure and add it to the procedures list
        
        Parameters
        ----------
        self: BinaryInfo
            This instance
        name: str
            The procedure name
        asm: str
            Assembly code
        raw: str
            The bytes of the procedure
        insns_list: list
            List of instructions in the procedure (in bytes)
        ops: str
            Concatenation of the first bytes of each instruction
        offset: int
            Location of the procedure in the binary
        callconv: str
            Calling convention (can be None if not recognized)
        flow: list
            List of matching.CallInsn or matching.JumpInsn instances
        """
        
        handler = matching.ProcedureHandler(raw, insns_list, offset, flow, self.arch)
        
        handler.handleFlow()
        
        handler.lift()
        
        proc = {
            "offset": offset,
            "proc_desc": {
                "name": name,
                "raw": base64.b64encode(raw),
                "asm": asm,
                "callconv": callconv,
                "apicalls": handler.api,
                "arch": self.arch.name
            }
        }

        
        proc["proc_desc"]["flow_hash"] = handler.flowhash.encode("hex")
        proc["proc_desc"]["vex_hash"] = handler.vexhash.encode("hex")
        proc["proc_desc"]["full_hash"] = hashlib.md5(raw).hexdigest()
        self.data["procs"].append(proc)

    def addString(self, string):
        self.data["strings"].append(string)

    def toJson(self):
        #return str(self.data)
        return json.dumps(self.data, indent=2, ensure_ascii=True)

    def __str__(self):
        return self.toJson()

        
    def _parseIDB(self, filename):
        
        import logging
        import idb
        import idblib
        
        logging.basicConfig()

        imports_map = {}        
        
        #############################################################
        #r2 cmd ilj : get imported libs in json
        print("3: getting imported libraries...")
        libs_list = self.r2.cmdj('ilj')
        self.data["libs"] = []
        for lib in libs_list:
            self.data["libs"].append({"name": lib})
        
        #r2 cmd ilj : get imported functions in json
        print("4: getting imported procedures names...")
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
        
        
        #r2 cmd ilj : get exported symbols in json
        print("5: getting exported symbols...")
        exports = self.r2.cmdj('iEj')
        
        self.data["exports"] = []
        for exp in exports:
            e = {
                "name": exp["name"],
                "offset": exp["paddr"],
                "size": exp["size"]
            }
            self.data["exports"].append(e)
        
        #r2 cmd aa : analyze all
        print("1: analyzing all...")
        self.r2.cmd("aaa")
        
        #############################################################
        
        def strz(b, o):
            return b[o:b.find(b'\x00', o)].decode('utf-8', 'ignore')

        def checkFlow(arch, mnem):
            if arch == 'metapc':
                return mnem == 'call', mnem.startswith('j')
            elif arch == 'avr':
                return 'call' in mnem, mnem.startswith('br') or 'jmp' in mnem
            elif arch.startswith('ppc'):
                return mnem == 'bl', mnem.startswith('b') and mnem != 'bl'
            elif arch.startswith('mips'):
                check = mnem.startswith(('j', 'b'))
                return check and 'l' in mnem, check and 'l' not in mnem
            elif arch.startswith('arm'):
                check = mnem.startswith('B')
                return check and 'L' in mnem, check and 'L' not in mnem
            else:
                return False, False   
         
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
        
        with idb.from_file(filename) as db:
            api = idb.IDAPython(db)

            ida_funcs = api.idautils.Functions()
            
            sym_imp_l = len("sym.imp")
            
            with status.Status(len(ida_funcs)) as bar:
                count = 0
                import sys
                #iterate for each function
                for func in ida_funcs:
                    #sys.stderr.write("begin: %d\n"%func)
                    try:
                        fcn_name = api.idc.GetFunctionName(func)
                        
                        start = api.idc.GetFunctionAttr(func, api.idc.FUNCATTR_START)
                        end = api.idc.GetFunctionAttr(func, api.idc.FUNCATTR_END)

                        cur_addr = start
                        
                        flow_insns = []
                        asm = ''
                        insns_list = []
                        opcodes_list = ""
                        
                        '''
                        get radare intructions, iterate, if not present assemble the single instruction.
                        s instr_addr
                        pdj 1 OR pdr
                        
                        sys.stderr.write("ppp1\n")'''
                        self.r2.cmd('s ' + hex(start))
                        sys.stderr.write(self.r2.cmd('pdrj'))
                        temp_d = self.r2.cmdj('pdrj')
                        sys.stderr.write("jj\n")
                        if temp_d == None:
                            temp_d = self.r2.cmdj('pdj')
                        
                        temp_d = []
                        temp_ins = {}
                        
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
                                    sys.stderr.write("jj\n")
                                    temp_d = self.r2.cmdj('pdrj')
                                    sys.stderr.write(self.r2.cmd('pdrj'))
                                    sys.stderr.write("\nCCCCC\n")
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
                                    continue
                                
                                #get the first byte in hex
                                first_byte = instr["bytes"][:2]
                                opcodes_list += first_byte
                                
                                #insert ops in codebytes (field with the frequency of each opcode, useful for ML)
                                self.data["codebytes"][first_byte] = self.data["codebytes"].get(first_byte, 0) +1
                                
                                
                                asm += hex(instr["offset"]) + "   " + instr["opcode"]
                                #get comment if possible
                                try:
                                    cmt = api.ida_bytes.get_cmt(cur_addr, True).replace('\n', ' ')
                                    asm += '   ;' + cmt
                                except:
                                    pass
                                asm += "\n" 
                                
                                
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
                                    jumpout = target < start or target >= end
                                    jump_instr = matching.JumpInsn(instr["offset"], instr["size"], target, jumpout)
                                    flow_insns.append(jump_instr)
                                
                                insns_list.append(instr["bytes"].decode("hex"))
                                    
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
                        fcn_call_conv = "(null)"
                        
                        '''
                        print('%x - %x' % (start, end))
                        print('++++ 0x%d %s ++++\n%s' % (func, fcn_name, asm))
                        for ii in flow_insns:
                            print ii
                        print
                        '''
                        self.addProc(fcn_name, asm, fcn_bytes, insns_list, opcodes_list.decode("hex"), start, fcn_call_conv, flow_insns)
                        
                    except Exception as err:
                        print asm
                        print err.message
                        print("error on function %s, skipped" % fcn_name)  
                    count += 1
                    bar.update(count)
        
        fhandle.close()
    
    def _IDAProTask(self, filename):
    
        print("2: Waiting for IDA to parse database (this may take several minutes)...")

        #.json name
        binname = os.path.splitext(filename)[0]
        rand = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
        dumpname = '.'+binname+ '-'+ rand +'-dump.json'

        file_ext = os.path.splitext(filename)[1]
        idascript = os.path.join(os.path.dirname(os.path.abspath(__file__)), "idascript.py ")
        
        if config.usewine:
            idascript.replace(os.path.sep, "\\")
        
        if file_ext == '.idb':
            process = subprocess.Popen(config.idacmd + ' -A -S"' + idascript + dumpname +'" "' + filename + '"', shell=True)
        elif file_ext == '.i64':
            process = subprocess.Popen(config.ida64cmd + ' -A -S"' + idascript + dumpname +'" "' + filename + '"', shell=True)
        else:
            raise RuntimeError('file not supported')
        process.wait()

        #getting data from idascript via json
        idadump = open(dumpname, 'r')
        data = json.load(idadump)
        idadump.close()

        #clean up
        os.remove(dumpname)
        
        print("2: getting file properties...")
        #self.data['info'] = data['info']
        for key in data['info']:
            self.data['info'][key] = data['info'][key]
        
        try:
            self.arch = matching.archFromIda(self.data["info"]["arch"], self.data["info"]["bits"], self.data["info"]["endian"])
        except:
            raise ArchNotSupported("arch %s not supported" % self.data["info"]["arch"])
        self.data["info"]["arch"] = self.arch.name
        
        print("3: getting imported libraries...")
        self.data['libs'] = data['libs']

        print("4: getting imported procedures names...")
        self.data['imports'] = data['imports']

        print("5: getting exported symbols...")
        self.data["exports"] = data['exports']

        print("6: getting assembly and other info about each procedure...")
        
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
                    
                    #insert ops in codebytes (field with the frequency of each opcode, useful for ML)
                    for i in range(0, len(opcodes_list), 2):
                        self.data["codebytes"][opcodes_list[i:i+2]] = self.data["codebytes"].get(opcodes_list[i:i+2], 0) +1
                    
                    fcn_offset = func['offset']
                    fcn_call_conv = func['callconv']
                    call_insns = func['call_insns']
                    jump_insns = func['jump_insns']
                    flow_insns = []
                    for ci in call_insns:
                        call_instr = matching.CallInsn(*(ci))
                        flow_insns.append(call_instr)
                    for ji in jump_insns:
                        jump_instr = matching.JumpInsn(*(ji))
                        flow_insns.append(jump_instr)             

                    self.addProc(fcn_name, asm, fcn_bytes, insns_list, opcodes_list.decode("hex"), fcn_offset, fcn_call_conv, flow_insns)
                except Exception as err:
                    print err
                    print("error on function %s, skipped" % func["name"])
                count += 1
                bar.update(count)

    def fromIdaDB(self, filename):
        '''
        Get information about binary stored in a IDA database

        :param str filename: The name of the IDA databse or its path
        '''
        
        if config.idacmd == None:
            print("IDA Pro not found, using built-in idb parsing module.\nThe output may not be accurate.")
            self._parseIDB(filename)
        else:
            self._IDAProTask(filename)

    def _r2Task(self):
        '''
        Get info from the radare2 process
        '''
        
        print("2: getting architecture...")
        try:
            self.arch = matching.archFromR2(self.data["info"]["arch"], self.data["info"]["bits"], self.data["info"]["endian"])
        except:
            raise ArchNotSupported("arch %s not supported" % self.data["info"]["arch"])
        self.data["info"]["arch"] = self.arch.name
        
        #r2 cmd ilj : get imported libs in json
        print("3: getting imported libraries...")
        libs_list = self.r2.cmdj('ilj')
        self.data["libs"] = []
        for lib in libs_list:
            self.data["libs"].append({"name": lib})
        
        #r2 cmd ilj : get imported functions in json
        print("4: getting imported procedures names...")
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
        
        #r2 cmd ilj : get exported symbols in json
        print("5: getting exported symbols...")
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
        print("6: getting list of analyzed procedures...")
        funcs_dict = self.r2.cmdj('aflj')
        sym_imp_l = len("sym.imp") 
        
        print("7: getting assembly and other info about each procedure...")
        with status.Status(len(funcs_dict)) as bar:
            count = 0
            for func in funcs_dict:
                try:
                #if True:
                    #skip library symbols
                    if len(func["name"]) >= sym_imp_l and func["name"][:sym_imp_l] == "sym.imp":
                        continue
                    
                    fcn_offset = func["offset"]
                    fcn_size = func["size"]
                    fcn_name = func["name"]
                    fcn_call_conv = func["calltype"]
                    
                    self.r2.cmd('s ' + hex(fcn_offset))
                    
                    #r2 cmd pdrj : get assembly from a function in json
                    fcn_instructions = self.r2.cmdj('pdrj')
                    
                    #r2 cmd p6e : get bytes of a function in base64
                    fcn_bytes = base64.b64decode(self.r2.cmd('p6e ' + str(fcn_size)).rstrip())
                    
                    insns_list = []
                    asm = ""
                    opcodes_list = ""
                    
                    flow_insns = []
                    targets = {}
                    
                    for instr in fcn_instructions:
                        if instr["type"] == "invalid":
                            break
                        
                        #get the first byte in hex
                        first_byte = instr["bytes"][:2]
                        opcodes_list += first_byte
                        
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
                    
                    self.addProc(fcn_name, asm, fcn_bytes, insns_list, opcodes_list.decode("hex"), fcn_offset, fcn_call_conv, flow_insns)
                except Exception as err:
                    print err
                    print("error on function %s, skipped" % func["name"])
                count += 1
                bar.update(count)

    def fromR2Project(self, name):
        '''
        Get information about binary stored in a radare2 project

        :param str name: The name of the radare2 project or its path
        '''

        print("[Retrieving info from radare2 project]")
        
        #set project directory var in radare
        projdir = os.path.dirname(name)
        projname = os.path.basename(name)
        if projdir != "":
            projdir = os.path.expanduser(projdir)
            self.r2.cmd("e dir.projects=" + projdir)
        
        #r2 cmd Po : load project
        print("1: loading project...")
        out = self.r2.cmd("Po " + projname)
        if len(out) >= len("Cannot open project info") and out == "Cannot open project info":
            raise RuntimeError("cannot load radare2 project " + name)
        
        self._r2Task()

    def generateInfo(self):
        '''
        Grab basic informations about the binary from r2
        '''

        print("[Extracting info from binary]")
        
        #r2 cmd aa : analyze all
        print("1: analyzing all...")
        self.r2.cmd("aaa")
        
        self._r2Task()



