#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, rop2bash@gmail.com"

import idautils
import idaapi
import idc
import os
import json
import base64

'''
info:
    program_class | OK
    arch | OK
    bits | OK
    endian | OK
procedures:
    name | OK
    raw | OK
    asm | OK
    ops | OK
    offset |OK
    flow_insns | OK
    insns_list | OK
    callconv | OK
imports | OK
exports | OK
libs | OK

architectures:
    x86/64 | OK
    avr | ON HOLD
    powerpc | OK
    mips | OK
    arm | OK
'''
class_map = {
    0:  'EXE_old',     # MS DOS EXE File
    1:  'COM_old',     # MS DOS COM File
    2:  'BIN',         # Binary File
    3:  'DRV',         # MS DOS Driver
    4:  'WIN',         # New Executable (NE)
    5:  'HEX',         # Intel Hex Object File
    6:  'MEX',         # MOS Technology Hex Object File
    7:  'LX',          # Linear Executable (LX)
    8:  'LE',          # Linear Executable (LE)
    9:  'NLM',         # Netware Loadable Module (NLM)
    10: 'COFF',        # Common Object File Format (COFF)
    11: 'PE',          # Portable Executable (PE)
    12: 'OMF',         # Object Module Format
    13: 'SREC',        # R-records
    14: 'ZIP',         # ZIP file (this file is never loaded to IDA database)
    15: 'OMFLIB',      # Library of OMF Modules
    16: 'AR',          # ar library
    17: 'LOADER',      # file is loaded using LOADER DLL
    18: 'ELF',         # Executable and Linkable Format (ELF)
    19: 'W32RUN',      # Watcom DOS32 Extender (W32RUN)
    20: 'AOUT',        # Linux a.out (AOUT)
    21: 'PRC',         # PalmPilot program file
    22: 'EXE',         # MS DOS EXE File
    23: 'COM',         # MS DOS COM File
    24: 'AIXAR',       # AIX ar library
    25: 'MACHO'        # Mac OS X
}

data = {
    'info' : {
        'program_class': None,
        'arch': None,
        'bits': None,
        'endian': None
    },
    'procedures': [],
    'imports': [],
    'exports': [],
    'libs': []
}

def imp_cb(ea, name, ord): #call-back function required by idaapi.enum_import_names()
    i = {
        'name': name,
        'addr': ea
    }
    data['imports'].append(i)
    return True

def getCallConv(func_info):
    if func_info != None and 'cdecl' in func_info:
       return 'cdecl'
    elif func_info != None and 'ellipsis' in func_info:
       return 'ellipsis'
    elif func_info != None and 'stdcall' in func_info:
       return 'stdcall'
    elif func_info != None and 'pascal' in func_info:
       return 'pascal'
    elif func_info != None and 'fastcall' in func_info:
       return 'fastcall'
    elif func_info != None and 'thiscall' in func_info:
       return 'thiscall'
    elif func_info != None and 'manual' in func_info:
       return 'manual'
    elif func_info != None and 'speciale' in func_info:
       return 'speciale'
    elif func_info != None and 'specialp' in func_info:
       return 'specialp'
    elif func_info != None and 'special' in func_info:
       return 'special'
    else:
       return ''

def theFlow(call_check, jump_check, flow_insns):
    if call_check:
        op = idc.GetOpnd(cur_addr, 0)
        op_type = idc.GetOpType(cur_addr, 0)
        op_val = GetOperandValue(cur_addr, 0)
        
        if (op_type == o_near or op_type == o_far or op_type == o_mem) and op_type != o_reg:
            isApi = False
            for imp in data['imports']:
                if isApi:
                    break
                if op == '_' + imp['name'] or op == imp['name']:
                        isApi = True
                        op = imp['name']
                        #target = imp['addr']
                        break
                for addr in idautils.CodeRefsTo(imp['addr'], 1):
                    if addr == cur_addr:
                        isApi = True
                        op = imp['name']
                        #target = imp['addr']
                        break
            target = op_val
            if target == BADADDR:
                target = idc.get_name_ea_simple(op)
                if target == BADADDR:
                    target = idc.get_name_ea_simple(op[1:])
            flow_insns.append((cur_addr, size, target, op, isApi))
    elif jump_check:
        op = idc.GetOpnd(cur_addr, 0)
        op_type = idc.GetOpType(cur_addr, 0)
        if (op_type == o_near or op_type == o_far) and op_type != o_reg:
            target = None
            jumpout = None
            target = idc.LocByName(op)
            jumpout = target  < start or target > end
            flow_insns.append((cur_addr, size, target, jumpout))

metapcFlow = theFlow
avrFlow = theFlow
ppcFlow = theFlow
mipsFlow = theFlow
armFlow = theFlow

def checkFlow(arch, mnem):
    if arch == 'metapc':
        return mnem == 'call', mnem.startswith('j'), metapcFlow
    elif arch == 'avr':
        return 'call' in mnem, mnem.startswith('br') or 'jmp' in mnem, avrFlow
    elif arch.startswith('ppc'):
        return mnem == 'bl', mnem.startswith('b') and mnem != 'bl', ppcFlow
    elif arch.startswith('mips'):
        check = mnem.startswith(('j', 'b'))
        return check and 'l' in mnem, check and 'l' not in mnem, mipsFlow
    elif arch.startswith('arm'):
        check = mnem.startswith('B')
        return check and 'L' in mnem, check and 'L' not in mnem, armFlow
    else:
        return False, False, theFlow

#wait for IDA analysys to complete
idaapi.autoWait()

#json to communicate with main process
dumpname = idc.ARGV[1]
dump = open(dumpname, 'w')

#get info
info = idaapi.get_inf_structure()

#get arch
data['info']['arch'] = info.procName.lower()

#get bits
if info.is_64bit():
    data['info']['bits'] = 64
elif info.is_32bit():
    data['info']['bits'] = 32
else:
    data['info']['bits'] = 16

#get endian
data['info']['endian'] = "little"
if info.is_be():
    data['info']['endian'] = "big"

#get program_class
data['info']['program_class'] = class_map[info.filetype]

#get imports and dlls
nimps = idaapi.get_import_module_qty()
for i in xrange(0, nimps):
    dllname = idaapi.get_import_module_name(i)
    if dllname != None:
        data['libs'].append({"name": dllname})
    idaapi.enum_import_names(i, imp_cb)

#get exports
for exp in list(idautils.Entries()):
    e = {
        'name': exp[3],
        'offset': exp[1],
        'size': 0 #Hardcoded to 0 until we figure out what the 'size' info actually means
    }
    data['exports'].append(e)

#iterate through functions
for func in idautils.Functions():
    #if func from library skip
    flags = idc.GetFunctionFlags(func)
    if flags & FUNC_LIB or flags & FUNC_THUNK or flags & FUNC_HIDDEN:
        continue

    #get procedure name
    name = idc.GetFunctionName(func)
    
    #get procedure callconv
    func_info = idc.GetType(func)
    callconv = getCallConv(func_info)
    
    start = idc.GetFunctionAttr(func, FUNCATTR_START)
    end = idc.GetFunctionAttr(func, FUNCATTR_END)
    cur_addr = start
    
    asm = ''
    ops = ''
    insns_list = []
    flow_insns = []

    while cur_addr <= end:
        next_instr = idc.NextHead(cur_addr, end)

        #get size instr
        if next_instr > end:
            size = end - cur_addr
        else:
            size = next_instr - cur_addr

        #get assembly and comments
        curr_asm = hex(cur_addr).rstrip("L") + "   " + idc.GetDisasm(cur_addr).split(';')[0]
        try:
            curr_asm += '   ;' + idc.GetCommentEx(cur_addr, True).replace('\n', ' ')
        except:
            pass
        curr_asm += '\n'
        asm += curr_asm

        #get first byte of instruction
        opc = hex(ord(idc.GetManyBytes(cur_addr, 1)))[2:]
        if len(opc) < 2:
            opc = '0'+opc
        ops += opc

        #get instruction bytes
        insns_list.append((cur_addr, base64.b64encode(idc.GetManyBytes(cur_addr, size))))
        
        #add to flow_insns if call or jump
        arch = data['info']['arch']
        mnem = idc.GetMnem(cur_addr) if arch =='metapc' else idc.GetDisasm(cur_addr).split()[0]
        call_check, jump_check, addFlow = checkFlow(arch, mnem)
        addFlow(call_check, jump_check, flow_insns)

        cur_addr = next_instr

    #get raw data
    raw_data = idc.GetManyBytes(start, end - start)

    proc_data = {
        'name': name,
        'offset': start,
        'callconv': callconv,
        'raw_data': base64.b64encode(raw_data),
        'asm': asm,
        'flow_insns': flow_insns,
        'insns_list': insns_list,
        'ops': ops
    }
    data['procedures'].append(proc_data)
    
json.dump(data, dump)

dump.close()

#stop script
idc.Exit(0)

