import sys
import resource
import time
import zlib
import argparse
from carbonara_bininfo import BinaryInfo

parser = argparse.ArgumentParser(prog='carbonara-cli')
parser.add_argument('binary_file', nargs=1, help='binary file to load')
group = parser.add_mutually_exclusive_group()
group.add_argument('-r2', '--r2-project', nargs=1, help='radare2 project to load')
group.add_argument('-idb', '--ida-db', nargs=1, help='IDA Pro databse to load')
args = parser.parse_args()

start_time = time.time()
bi = BinaryInfo(args.binary_file[0])
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

