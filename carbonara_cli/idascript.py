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
name | OK
raw | OK
asm | OK
offset |OK
flow_insns | OK
callconv | TODO => PROB NOT POSSIBLE
'''

#wait for IDA analysys to complete
idaapi.autoWait()

#DEBUG
f = open('debug.txt', 'w')

dump = open('dump.json', 'w')

data = {
   'procedures' : []
}

#iterate trhough functions
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

    call_insns = []
    jmp_insns = []
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

        #check if api call/jump
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

            call_insns.append((cur_addr, size, target, func_name))

        elif mnem == 'jmp':
            op = idc.GetOpnd(cur_addr, 0)
            op_type = idc.GetOpType(cur_addr, 0)

            target = None
            jumpout = None

            if op_type == o_near or op_type == o_far:
                target = idc.LocByName(op)
                jumpout = target  < start or target > end
                

            jmp_insns.append((cur_addr, size, target, jumpout))

        cur_addr = next_instr


    #get raw data
    raw_data = idc.GetManyBytes(start, end - start)

    #DEBUG
    f.write(hex(start)[:-1] +' '+ name+ ';flags: '+hex(flags)[:-1]+'\ncall_insns: '+ str(call_insns)+'; jmp_insns: '+str(jmp_insns)+'\n')
    f.write(asm)
    f.write('\n')
    #f.write(raw_data)

    proc_data = {
        'name' : name,
        'offset' : start,
        'raw_data' : base64.b64encode(raw_data),
        'asm' : asm,
        'call_insns' : call_insns,
        'jmp_insns' : jmp_insns
    }
    data['procedures'].append(proc_data)

json.dump(data, dump)

f.close()
dump.close()

#stop script
idc.Exit(0)