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

#iterate through segments
for seg in idautils.Segments():
	print idc.SegName(seg), idc.SegStart(seg), idc.SegEnd(seg)

#iterate trhough functions
for func in idautils.Functions():

	#if func from library skip
	flags = idc.GetFunctionFlags(func)
	if flags & FUNC_LIB:
		continue

	#get procedure name
	name = idc.GetFunctionName(func)
	
	#get assembly
	start = idc.GetFunctionAttr(func, FUNCATTR_START)
	end = idc.GetFunctionAttr(func, FUNCATTR_END)
	cur_addr = start

	asm = ''

	while cur_addr <= end:
		asm += hex(cur_addr) + ' ' + idc.GetDisasm(cur_addr) +'\n'
		cur_addr = idc.Nexthead(cur_addr, end)

	#get raw data
	raw_data = idc.getManyBytes(start, end - start)

	f.write(start +' '+ name+'\n')
	f.write(asm)

f.close()

#stop script
idc.Exit(0)