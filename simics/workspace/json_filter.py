#!/usr/bin/python3
'''
Sample RESim AFL filter to replace an item in a Json list with the given data
'''
import json
import os
import sys
import binascii
from struct import *

'''
The filter method gets data and a packet number from the calling RESim afl function.  
The packet number is not used in this example.
'''
def filter(data, packet_num):
    # change this fname to the json file whose content is to be replaced.
    fname = './starting.json'
    # change replace_index to the index within the json of the item to be replaced
    replace_index = 4
    the_json = None
    if not os.path.isfile(fname):
        print('No file at %s' % fname)
        return
    with open(fname) as fh:
        the_json = json.load(fh)
    # The json entry must be a string, so use hexlify to make one
    data_str = str(binascii.hexlify(data))
    # Replace the json item with the hexlified data
    the_json[replace_index] = data_str
    # Return the json string to RESim for injection 
    retval = json.dumps(the_json)
    return retval

if __name__ == '__main__':
    
    # This "main" function is not used within RESim.  It is here for testing.
    # Run the python script, passing in the name of a file that contains test
    # data that is to replace a json entry.  The resuling json is written to
    # /tmp/tst_filter.json
    if len(sys.argv) < 2:
        print('provide file name')
        exit(1)
    f = sys.argv[1]
    print('loading data from %s' % f)
    data = None
    with open(f, 'rb') as fh:
        data = fh.read()
    fdata = filter(data, 1)
    outfile = '/tmp/tst_filter.json'
    with open(outfile, 'w') as fh:
        fh.write(fdata)
    print('wrote %d bytes to %s' % (len(fdata), outfile))
