#!/usr/bin/env python3
import sys
fname = sys.argv[1]
hdr = sys.argv[2]
pnum = int(sys.argv[3])
print('extract packet number %d using header %s from file %s' % (pnum, hdr, fname))
with open(fname, 'br') as fh:
    data = fh.read()
    hdr = hdr.encode()
    count = data.count(hdr)
    print('see %d headers' % count)
    if count > pnum:
        index = data.find(hdr, pnum)
        next_hdr = pnum+1
        end = data.find(hdr, next_hdr)
        newdata = data[index:end]
        with open('/tmp/extracted.io', 'bw') as out:
            out.write(newdata)
            print('wrote %d bytes to /tmp/extracted.io' % (len(newdata)))
