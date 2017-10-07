#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, willownoises@gmail.com"

import sys
import time
import zlib
import resource
import argparse
import carbonara_bininfo as carb

parser = argparse.ArgumentParser(prog='carbonara-cli', version='1.0alpha')
parser.add_argument('binary_file', nargs=1, help='binary file to analyze')
group = parser.add_mutually_exclusive_group()
group.add_argument('-r2', '--r2-project', nargs=1, help='radare2 project to load')
group.add_argument('-idb', '--ida-db', nargs=1, help='IDA Pro database to load')
parser.add_argument('-idacmd', '--ida-command', nargs=1, help='IDA Pro start command (ex. C:\\Program Files\\IDA 7.0\\ida.exe)')
parser.add_argument('-reconfig', '--refresh-config', action='store_true', help='force to regenerate config file')
args = parser.parse_args()

if args.refresh_config:
    carb.populateConfig()

start_time = time.time()

bi = carb.BinaryInfo(args.binary_file[0])
if args.ida_db != None:
    bi.fromIdb(args.ida_db[0])
elif args.r2_project != None:
    bi.fromR2Project(args.r2_project[0])
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
print "memory usage: " + str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024) + " MB"
print "elapsed time: " + str(time.time() - start_time)

