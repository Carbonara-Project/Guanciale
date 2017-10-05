#!/usr/bin/env python

import json
import base64
import hashlib
import idb
import progressbar
import binascii
import idblib
import struct
import os.path
import our_r2pipe as r2pipe

class Procedure(object):
    def __init__(self, asm, raw, ops, offset, callconv):
        '''
        Procedure

        :param str asm: The disassembly with comments
        :param str raw: The bytes of the function
        :param str ops: List of first bytes of each instruction
        :param integer offset: The offset of function from the binary base address
        '''
        
        self.data = {
            "raw": raw,
            "asm": asm,
            "offset": offset,
            "callconv": callconv
        }
        #hash of level 1: sha256 of the first bytes of each instruction
        hash_object = hashlib.sha256(ops)
        hex_dig = hash_object.hexdigest()
        self.data["hash1"] = hash_object.hexdigest()
        #hash of level 2: sha256 of the entire function code
        hash_object = hashlib.sha256(raw)
        hex_dig = hash_object.hexdigest()
        self.data["hash2"] = hash_object.hexdigest()
    
    def toJson(self):
        return json.dumps(self.data, ensure_ascii=True, cls=_JsonEncoder)

    def __str__(self):
        return self.toJson()


class BinaryInfo(object):
    def __init__(self, filename):
        '''
        BinaryInfo

        :param str filename: The filename of target binary
        '''
        
        print "[Retrieving basic info about binary]"
        self.data = {
            "procs": {}
        }
        #open radare2 as subprocess
        self.r2 = r2pipe.open(filename)
        #r2 cmd iIj : get info about binary in json
        print "1: getting info about file..."
        self.data["info"] = self.r2.cmdj('iIj')
        #r2 cmd izzj : get strings contained in the binary in json
        print "2: getting strings list..."
        self.data["strings"] = self.r2.cmdj('izzj')["strings"]
        print "3: calculating entropy..."
        self.data["entropy"] = self.r2.cmdj('p=ej')

    def __del__(self):
        self.r2.quit()

    def addProc(self, name, proc):
        self.data["procs"][name] = proc
    
    def addString(self, string):
        self.data["strings"].append(string)
    
    def toJson(self):
        return json.dumps(self.data, ensure_ascii=True, cls=_JsonEncoder)
    
    def __str__(self):
        return self.toJson()

    def fromIdb(self, filename):
        '''
        Get information about binary stored in a IDA database

        :param str filename: The filename of the associated IDA database
        '''

        print "[Retrieving info from IDA db]"
        #open database from filename
        fhandle = open(filename, 'r')
        idbfile = idblib.IDBFile(fhandle)
        id0 = idblib.ID0File(idbfile, idbfile.getpart(0))

        #get architecture info
        root = id0.nodeByName("Root Node")
        params = id0.bytes(root, 'S', 0x41b994)
        magic, version, cpu, idpflags, demnames, filetype, coresize, corestart, ostype, apptype = struct.unpack_from("<3sH8sBBH" + (id0.fmt * 2) + "HH", params, 0)
        cpu = self.strz(cpu, 0)
        fhandle.close()

        with idb.from_file(filename) as db:
            api = idb.IDAPython(db)
            #iterate for each function
            for ea in api.idautils.Functions():
                #get function name
                name = api.idc.GetFunctionName(ea)
                address = ea
                asm = ''
                while True:
                    try:
                        #get assembly from function
                        op = api.idc._dissassemble(address)
                        asm += op.mnemonic+' '+op.op_str+'\n'

                        address += api.idc.ItemSize(address)
                    except:
                        break
                #get raw bytes from function
                raw = api.idc.GetManyBytes(ea, address-ea)
                if len(raw) > 0:
                    #get the first byte of the function in hex; ugly to see but works well
                    byte_hex = hex(ord(raw[0]))[2:][:2]
                    self.addProc(name, Procedure(asm, raw, byte_hex, address, "cdecl")) #TODO get calling convention

    def _r2Process(self):
        '''
        Get info from the radare2 process
        '''
        
        #r2 cmd ilj : get imported libs in json
        print "2: getting imported libraries..."
        self.data["libs"] = self.r2.cmdj('ilj')
        #r2 cmd ilj : get imported functions in json
        print "3: getting imported procedures names..."
        self.data["imports"] = self.r2.cmdj('iij')
        #r2 cmd ilj : get exported symbols in json
        print "4: getting exported symbols..."
        self.data["symbols"] = self.r2.cmdj('isj')
        #r2 cmd p=ej : calculate entropy
        #r2 cmd aflj : get info about analyzed functions
        print "5: getting list of analyzed procedures..."
        funcs_dict = self.r2.cmdj('aflj')
        l = len("sym.imp")
        print "6: getting assembly and other info about each procedure..."
        with progressbar.ProgressBar(max_value=len(funcs_dict)) as bar:
            count = 0
            for func in funcs_dict:
                try:
                    #skip library symbols
                    if len(func["name"]) >= l and func["name"][:l] == "sym.imp":
                        continue
                    offset = func["offset"]
                    callconv = func["calltype"]
                    #r2 cmd pdfj : get assembly from a function in json
                    asmj = self.r2.cmdj('pdfj @ ' + func["name"])
                    #r2 cmd prf : get bytes of a function
                    raw = self.r2.cmd('prfj @ ' + func["name"] + ' | base64')[1:] #strip newline at position 0
                    
                    asm = ""
                    ops = ""
                    for instr in asmj["ops"]:
                        if instr["type"] == "invalid":
                            continue
                        ops += instr["bytes"][:2]
                        if "comment" in instr:
                            asm += instr["opcode"] + "  ; " + base64.b64decode(instr["comment"]) + "\n"
                        else:
                            asm += instr["opcode"] + "\n"
                    
                    self.addProc(func["name"], Procedure(asm, raw, ops.decode("hex"), offset, callconv))
                except:
                    pass
                count += 1
                bar.update(count)

    def fromR2Project(self, name):
        '''
        Get information about binary stored in a radare2 project

        :param str name: The name of the radare2 project or its path
        '''
        
        print "[Retrieving info from radare2 project]"
        #r2 cmd Po : load project
        print "1: loading project..."
        projdir = os.path.dirname(name)
        projname = os.path.basename(name)
        if projdir != "":
            projdir = os.path.expanduser(projdir)
            self.r2.cmd("e dir.projects=" + projdir)
        out = self.r2.cmd("Po " + projname)
        if len(out) >= len("Cannot open project info") and out == "Cannot open project info":
            raise RuntimeError("cannot load radare2 project " + name)
        self._r2Process()

    def generateInfo(self):
        '''
        Grab basic informations about the binary from r2
        '''
        
        print "[Retrieving info about procedures]"
        #r2 cmd aa : analyze all
        print "1: analyzing all..."
        self.r2.cmd("aaa")
        self._r2Process()

class _JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, BinaryInfo) or isinstance(obj, Procedure):
            return obj.data
        return json.JSONEncoder.default(self, obj)

