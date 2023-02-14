#!/usr/bin/env python3
import sys
if len(sys.argv) != 4:
    print('extractPacket.py file hdr packet-number')
    exit(0)
fname = sys.argv[1]
hdr = sys.argv[2]
pnum = int(sys.argv[3])
print('extract packet number %d using header %s from file %s' % (pnum, hdr, fname))
with open(fname, 'br') as fh:
    data = fh.read()
    hdr = hdr.encode()
    count = data.count(hdr)
    print('see %d headers' % count)
    ''' ui is 1 relative '''
    if pnum <= 0:
        print('packet number is 1 relative')
    elif count > pnum:
        parts = data.split(hdr)
        newdata = hdr+parts[pnum]
        with open('/tmp/extracted.io', 'bw') as out:
            out.write(newdata)
            print('wrote %d bytes to /tmp/extracted.io' % (len(newdata)))
    else:
        print('not that many packets')
