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
info: (Where is even located all this info in IDA?) (edit: God bless tmr232 from StackOverflow)
    program_class | TODO
    arch | OK
    bits | OK
    endian | SO CLOSE YET SO FAR
procedures:
    name | OK
    raw | OK
    asm | OK
    offset |OK
    flow_insns | OK
    callconv | TODO => PROB NOT POSSIBLE (i love IDA)
ops | OK
imports | TODO
exports | TODO
libs | TODO
'''

#wait for IDA analysys to complete
idaapi.autoWait()

#DEBUG
f = open('debug.txt', 'w')

dump = open('dump.json', 'w')

data = {
    'info' : { #TODO
        'program_class' : None,
        'arch' : None,
        'bits' : None,
        'endian' : None
    },
    'procedures' : [],
    'ops' : [],
    'imports' : [],
    'exports' : [],
    'libs' : []
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

'''
#get endian
data['info']['endian'] = "little"
if info.mf:
    data['info']['endian'] = "big"
'''

#iterate through functions
for func in idautils.Functions():

    #if func from library skip
    flags = idc.GetFunctionFlags(func)
    if flags & FUNC_LIB or flags & FUNC_THUNK or flags & FUNC_HIDDEN:
        continue

    #get procedure name
    name = idc.GetFunctionName(func)
    
    start = idc.GetFunctionAttr(func, FUNCATTR_START)
    end = idc.GetFunctionAttr(func, FUNCATTR_END)
    cur_addr = start

    flow_insns = []
    asm = ''

    while cur_addr <= end:
        next_instr = idc.NextHead(cur_addr, end)

        #get size instr
        if next_instr > end:
            size = end - cur_addr
        else:
            size = next_instr - cur_addr

        #get assembly and comments
        asm += hex(cur_addr)[:-1] + ' ' + idc.GetDisasm(cur_addr) +'\n'

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
        elif mnem == 'jmp':
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

    #get first byte of procedure
    data['ops'].append(hex(ord(raw_data[0]))[2:][:2])

    #DEBUG
    f.write(hex(start)[:-1] +' '+ name+ ';flags: '+hex(flags)[:-1]+'\nflow_insns: '+ str(flow_insns)+'\n')
    #f.write(asm)
    f.write('\n')
    #f.write(raw_data)

    proc_data = {
        'name' : name,
        'offset' : start,
        'raw_data' : base64.b64encode(raw_data),
        'asm' : asm,
        'flow_insns' : flow_insns
    }
    data['procedures'].append(proc_data)

f.write(data['info']['arch']+" "+str(data['info']['bits'])+"\n"+str(data['ops'])+'\n')
json.dump(data, dump)

f.close()
dump.close()

#stop script
idc.Exit(0)