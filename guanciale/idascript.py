#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, willownoises@gmail.com"

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
    25: 'MACHO'        # Max OS X
}

#wait for IDA analysys to complete
idaapi.autoWait()

#json to communicate with main process
dump = open('dump.json', 'w')

data = {
    'info' : { #TODO
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

#get info
info = idaapi.get_inf_structure()

#get arch
data['info']['arch'] = info.procName

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
def imp_cb(ea, name, ord): #call-back function required by idaapi.enum_import_names()
    i = {
        'name': name,
        'addr': ea
    }
    data['imports'].append(i)
    return True

nimps = idaapi.get_import_module_qty()
for i in xrange(0, nimps):
    dllname = idaapi.get_import_module_name(i)
    data['libs'].append(dllname)
    idaapi.enum_import_names(i, imp_cb)

#get exports
for exp in list(idautils.Entries()):
    e = {
        'name': exp[3],
        'addr': exp[1],
        'size': None #TODO
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
    func_info = idc.GetType(start)
    if func_info != None and 'cdecl' in func_info:
        callconv = 'cdecl'
    elif func_info != None and 'ellipsis' in func_info:
        callconv = 'ellipsis'
    elif func_info != None and 'stdcall' in func_info:
        callconv = 'stdcall'
    elif func_info != None and 'pascal' in func_info:
        callconv = 'pascal'
    elif func_info != None and 'fastcall' in func_info:
        callconv = 'fastcall'
    elif func_info != None and 'thiscall' in func_info:
        callconv = 'thiscall'
    elif func_info != None and 'manual' in func_info:
        callconv = 'manual'
    elif func_info != None and 'speciale' in func_info:
        callconv = 'speciale'
    elif func_info != None and 'specialp' in func_info:
        callconv = 'specialp'
    elif func_info != None and 'special' in func_info:
        callconv = 'special'
    else:
        callconv = ''
    
    start = idc.GetFunctionAttr(func, FUNCATTR_START)
    end = idc.GetFunctionAttr(func, FUNCATTR_END)
    cur_addr = start
    
    flow_insns = []
    asm = ''
    ops = []
    insns_list = []
    while cur_addr <= end:
        next_instr = idc.NextHead(cur_addr, end)

        #get size instr
        if next_instr > end:
            size = end - cur_addr
        else:
            size = next_instr - cur_addr

        #get assembly and comments
        curr_asm = hex(cur_addr)[:-1] + ' ' + idc.GetDisasm(cur_addr).split(';')[0]
        try:
            curr_asm += '   ;' + idc.GetCommentEx(cur_addr, True).replace('\n', ' ')
        except:
            pass
        curr_asm += '\n'
        asm += curr_asm

        #get first byte of instruction
        ops.append(hex(ord(idc.GetManyBytes(cur_addr, 1)))[2:])

        #get instruction bytes
        insns_list.append(base64.b64encode(idc.GetManyBytes(cur_addr, size)))

        #add to flow_insns if call or jump
        mnem = idc.GetMnem(cur_addr)
        if mnem == 'call':
            op = idc.GetOpnd(cur_addr, 0)
            op_type = idc.GetOpType(cur_addr, 0)
            if op[0] == '_': #temp test if api (not 100% reliable)
                func_name = op[1:]
            else:
                func_name = op
            target = None
            if op_type == o_near or op_type == o_far:
                target = idc.LocByName(op)
            flow_insns.append((cur_addr, size, target, func_name))
        elif mnem.startswith('j'):
            op = idc.GetOpnd(cur_addr, 0)
            op_type = idc.GetOpType(cur_addr, 0)
            target = None
            jumpout = None
            if op_type == o_near or op_type == o_far:
                target = idc.LocByName(op)
                jumpout = target  < start or target > end
            flow_insns.append((cur_addr, size, target, jumpout))

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