import sys
import resource
import time
import zlib
from carbonara_bininfo import BinaryInfo

def usage():
    print "usage: "
    print "  carbonara_cli <binary file>"
    print "  carbonara_cli <binary file> <disassembler database>"
    print

if len(sys.argv) < 2:
    usage()
    exit()

start_time = time.time()
bi = BinaryInfo(sys.argv[1])
if len(sys.argv) > 2:
    bi.fromIdb(sys.argv[2])
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

