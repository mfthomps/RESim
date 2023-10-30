#!/usr/bin/env python3
#
# Apply an AFL packet filter to each unique (deduped) queue file to reflect what RESim 
# injected.
#
import sys
import os
import glob
import json
try:
    import ConfigParser
except:
    import configparser as ConfigParser
import argparse
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
import resimUtils
def getFilter(ini):
    config = ConfigParser.ConfigParser()
    config.read(ini)
    retval = None
    if not config.has_option('ENV', 'AFL_PACKET_FILTER'):
        print('no AFL_PACKET_FILTER')
    else:
        retval = config.get('ENV', 'AFL_PACKET_FILTER')
        print('found filter: %s' % retval)
    return retval

def doFilter(flist, filter_module):
    for q in flist:
        data = None
        with open(q, 'rb') as fh:
            data = bytearray(fh.read())
            #ba = bytearray(data.encode('hex'))
        new_data = filter_module.filter(data, None) 
        with open(dumb_file, 'wb') as fh:
            fh.write(q)


def main():
    parser = argparse.ArgumentParser(prog='applyFilter', description='Apply an AFL filter to all deduped (unique) queue files.')
    parser.add_argument('ini', action='store', help='The ini file')
    parser.add_argument('target', action='store', help='The target program')
    args = parser.parse_args()
    queue_list = aflPath.getTargetQueue(args.target)
    if len(queue_list) == 0:
        print('No queue files found for %s' % args.target)
        sys.exit(1)
    else:
        print('Will filter %d queue files' % len(queue_list))
    packet_filter = getFilter(args.ini)
    lgr = resimUtils.getLogger('applyFiter', '/tmp')
    filter_module = None
    if packet_filter is not None:
            filter_module = resimUtils.getPacketFilter(packet_filter, lgr)
    else:
        print('Unable to get filter name from %s' % args.ini)
        sys.exit(1)
    doFilter(queue_list, filter_module)
    #crash_list = aflPath.getTargetCrashes(args.target)
    #doFilter(crash_list)

if __name__ == '__main__':
    sys.exit(main())
