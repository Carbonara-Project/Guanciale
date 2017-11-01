#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, willownoises@gmail.com"

import idautils
import idaapi
import idc
import os

'''
name | OK
raw ! OK
asm | OK
offset |OK
apicalls | TODO
callconv | TODO
'''

#wait for IDA analysys to complete
idaapi.autoWait()

#DEBUG
f = open('debug.txt', 'w')

f.write('o_mem: '+str(o_mem)+'\n')
f.write('o_far: '+str(o_far)+'\n')
f.write('o_near: '+str(o_near)+'\n')



#iterate trhough functions
for func in idautils.Functions():

	#if func from library skip
	flags = idc.GetFunctionFlags(func)
	if flags & FUNC_LIB:
		continue
	if flags & FUNC_THUNK:
		continue
	if flags & FUNC_HIDDEN:
		continue

	#get procedure name
	name = idc.GetFunctionName(func)
	
	#get assembly
	start = idc.GetFunctionAttr(func, FUNCATTR_START)
	end = idc.GetFunctionAttr(func, FUNCATTR_END)
	cur_addr = start

	apicalls = []
	asm = ''

	while cur_addr <= end:
		asm += hex(cur_addr) + ' ' + idc.GetDisasm(cur_addr) +'\n'

		#check if api call/jump
		mnem = idc.GetMnem(cur_addr)
		if mnem == 'call' or mnem == 'jmp':
			op = idc.GetOpnd(cur_addr, 0)
			op_type = idc.GetOpType(cur_addr, 0)
			#addr = idc.LocByname(op)
			#check = idc.GetFunctionFlags(addr)
			apicalls.append((op, op_type))


		cur_addr = idc.NextHead(cur_addr, end)


	#get raw data
	raw_data = idc.GetManyBytes(start, end - start)

	#DEBUG
	f.write(hex(start)[:-1] +' '+ name+ ';flags: '+hex(flags)[:-1]+'\napicalls: '+ str(apicalls)+ '\n')
	#f.write(asm)
	#f.write('\n')

f.close()

#stop script
idc.Exit(0)