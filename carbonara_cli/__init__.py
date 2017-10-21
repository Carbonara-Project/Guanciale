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

class BinaryInfo(object):
    def __init__(self, filename):
        '''
        BinaryInfo

        :param str filename: The filename of target binary
        '''

        print "[Retrieving basic info about binary]"
        #open the binary file and compute sha256 hash
        binfile = open(filename, "rb")
        hash_object = hashlib.sha256(binfile.read())
        hex_dig = hash_object.hexdigest()
        binfile.close()

        self.data = {
            "program": { "sha256": hex_dig },
            "procs": [],
            "codebytes": {}
        }

        #open radare2 as subprocess
        self.r2 = r2handler.open(filename)
        #r2 cmd iIj : get info about binary in json
        print "1: getting info about file..."
        self.data["info"] = self.r2.cmdj('iIj')
        self.data["info"]["program_class"] = self.data["info"]["class"] #needed in the backend
        #r2 cmd izzj : get strings contained in the binary in json
        print "2: getting strings list..."
        self.data["strings"] = self.r2.cmdj('izzj')["strings"]
        print "3: calculating entropy..."
        self.data["entropy"] = self.r2.cmdj('p=ej')

    def __del__(self):
        if "r2" in self.__dict__:
            self.r2.quit()

    def addProc(self, name, asm, raw, ops, offset, callconv, apicalls):
        '''
        generate a dictionary with the informations needed to describe a procedure and add it to the procedures list

        :param str name: The procedure name
        :param str asm: The disassembly with comments
        :param str raw: The bytes of the function
        :param str ops: List of first bytes of each instruction
        :param integer offset: The offset of function from the binary base address
        :param array<string> apicalls: List of external API called in the procedure
        '''

        proc = {
            "name": name,
            "raw": raw,
            "asm": asm,
            "offset": offset,
            "callconv": callconv,
            "apicalls": apicalls
        }
        #hash of level 1: sha256 of the first bytes of each instruction
        hash_object = hashlib.sha256(ops)
        hex_dig = hash_object.hexdigest()
        proc["hash1"] = hash_object.hexdigest()
        #hash of level 2: sha256 of the entire function code
        hash_object = hashlib.sha256(raw)
        hex_dig = hash_object.hexdigest()
        proc["hash2"] = hash_object.hexdigest()
        #add proc to list
        self.data["procs"].append(proc)

    def addString(self, string):
        self.data["strings"].append(string)

    def toJson(self):
        return json.dumps(self.data, ensure_ascii=True)

    def __str__(self):
        return self.toJson()

    def fromIdb(self, filename):
        '''
        Get information about binary stored in a IDA database

        :param str filename: The filename of the associated IDA database
        '''

        
        def strz(b, o):
            return b[o:b.find(b'\x00', o)].decode('utf-8', 'ignore')

        def loadDis(api, mode):
            if api.idc.dis is not None:
                return

            # WARNING:
            # TODO: map IDA arch to capstone's to add support other than x86
            api.idc.dis = capstone.Cs(capstone.CS_ARCH_X86, mode)
            # required to fetch operand values
            api.idc.dis.detail = True

        def disassemble(ea, mode):
            size = api.idc.ItemSize(ea)
            buf = api.idc.GetManyBytes(ea, size)
            loadDis(api, mode)
            try:
                op = next(api.idc.dis.disasm_lite(buf, size))
            except StopIteration:
                raise RuntimeError('failed to disassemble %s' % (hex(ea)))
            else:
                return op

        def getAsm(api, address, mode):
            asm = ''
            flags = api.idc.GetFlags(address)
            if api.ida_bytes.isCode(flags):
                op = disassemble(api, address, mode)
                asm = hex(address)+' '+op[2]+' '+op[3]
                #also get comment if possible
                try:
                    cmt = api.ida_bytes.get_cmt(address, True).replace('\n', ' ')
                    asm += '   ;'+cmt
                except:
                    pass
            return asm+'\n'

        print "[Retrieving info from IDA db]"

        #extract and check file extension
        file_ext = os.path.splitext(filename)[1]
        if file_ext == '.idb':
            mode = capstone.CS_MODE_32
        elif file_ext == '.i64':
            mode = capstone.CS_MODE_64
        else:
            raise RuntimeError('file not supported')
            return

        #open database from filename
        fhandle = open(filename, 'r')
        idbfile = idblib.IDBFile(fhandle)
        id0 = idblib.ID0File(idbfile, idbfile.getpart(0))

        #get architecture info TODO map to capston
        root = id0.nodeByName("Root Node")
        params = id0.bytes(root, 'S', 0x41b994)
        magic, version, cpu, idpflags, demnames, filetype, coresize, corestart, ostype, apptype = struct.unpack_from("<3sH8sBBH" + (id0.fmt * 2) + "HH", params, 0)
        cpu = strz(cpu, 0)
        fhandle.close()

        with idb.from_file(filename) as db:
            api = idb.IDAPython(db)
            #iterate for each function
            funcs = api.idautils.Functions()
            with progressbar.ProgressBar(max_value=len(funcs)) as bar:
                count = 0
                for ea in funcs:
                    #get function name
                    name = api.idc.GetFunctionName(ea)
                    address = ea
                    asm = ''
                    #get assembly and comments from procedure
                    while True:
                        try:
                            asm += getAsm(api, address, mode)
                            address += api.idc.ItemSize(address)
                        except:
                            break
                    #get raw bytes from function
                    raw = api.idc.GetManyBytes(ea, address-ea)
                    if len(raw) > 0:
                        #get the first byte of the function in hex; ugly to see but works well
                        byte_hex = hex(ord(raw[0]))[2:][:2]
                        #insert byte_hex in codebytes
                        self.data["codebytes"][byte_hex] = self.data["codebytes"].get(byte_hex, 0) +1
                        self.addProc(name, asm, raw, byte_hex, address, "cdecl", []) #TODO get calling convention and api calls
                    count += 1
                    bar.update(count)


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
        sym_imp_l = len("sym.imp")
        print "6: getting assembly and other info about each procedure..."
        with progressbar.ProgressBar(max_value=len(funcs_dict)) as bar:
            count = 0
            for func in funcs_dict:
                try:
                    #skip library symbols
                    if len(func["name"]) >= sym_imp_l and func["name"][:sym_imp_l] == "sym.imp":
                        continue
                    offset = func["offset"]
                    callconv = func["calltype"]
                    #r2 cmd pdfj : get assembly from a function in json
                    asmj = self.r2.cmdj('pdfj @ ' + func["name"])
                    #r2 cmd prf : get bytes of a function
                    raw = self.r2.cmd('prfj @ ' + func["name"] + ' | base64')[1:] #strip newline at position 0

                    asm = ""
                    ops = ""
                    apicalls = []
                    for instr in asmj["ops"]:
                        if instr["type"] == "invalid":
                            continue
                        #get the first byte in hex
                        first_byte = instr["bytes"][:2]
                        ops += first_byte
                        #insert ops in codebytes
                        self.data["codebytes"][first_byte] = self.data["codebytes"].get(first_byte, 0) +1
                        #insert comments in disassembly if presents
                        if "comment" in instr:
                            asm += instr["opcode"] + "  ; " + base64.b64decode(instr["comment"]) + "\n"
                        else:
                            asm += instr["opcode"] + "\n"
                        #check if the instruction is of type 'call'
                        try:
                            if instr["type"] == "call":
                                arg = instr["opcode"].split()[-1]
                                if arg[:sym_imp_l] == "sym.imp":
                                    apicalls.append(arg[sym_imp_l +1:])
                                if arg[:len("sub.")] == "sub.":
                                    apicalls.append(arg[len("sub."):])
                        except: pass

                    self.addProc(func["name"], asm, raw, ops.decode("hex"), offset, callconv, apicalls)
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



