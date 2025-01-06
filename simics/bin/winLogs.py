#!/usr/bin/env python3
#
#
import sys
import os
import argparse
import glob
def getTokenValue(line, token):
    retval = None
    if token in line:
        parts = line.split(token, 1)
        remain = parts[1].strip()
        tparts = remain.split(' ')
        retval = tparts[0].strip()
    return retval

def main():
    thread_handles = {}
    parser = argparse.ArgumentParser(prog='winLogs', description='Find windows log messages in trace files.')
    parser.add_argument('trace_file', action='store', help='The trace file')
    args = parser.parse_args()
    if os.path.isfile(args.trace_file):
        flist = [args.trace_file]
    elif os.path.isdir(args.trace_file):
        glob_mask = '%s/*.trace' % (args.trace_file)
        flist = glob.glob(glob_mask)
        flist.sort(key=os.path.getmtime)
        if len(flist) == 0:
            print('No file found in %s' % glob_mask)
        else:
            for f in flist:
                print('trace file: %s' % f)
    else:
        print('Failed to find trace file at %s' % args.trace_file)
        exit(1)
    log_handle = None
    for trace_file in flist:
        with open(trace_file) as fh:
            for line in fh:
                line = line.strip()
                tid = getTokenValue(line, 'tid:')
                if tid is None:
                    continue
                pid = tid.split('-')[0]
                if 'return from' in line and 'CONNECT' in line and ':514 ' in line:
                    handle_s = getTokenValue(line, 'CONNECT FD:')                
                    log_handle = int(handle_s) 
                    thread_handles[pid] = log_handle
                    print('Set log handle to 0x%x for pid %s' % (log_handle, pid))
                elif pid in thread_handles:
                    if 'SEND' in line and 'return from' in line:
                        fd = getTokenValue(line, 'handle:')
                        try:
                            log_handle = int(fd, 16) 
                            #print('see log handle 0x%x' % log_handle)
                        except:
                            print('failed to get fd value from %s, line was %s' % (fd, line))
                            exit(1)
                        if log_handle == thread_handles[pid]:
                            data = line.split('data:', 1)[1]
                            output = '%s -- %s' % (tid, data)
                            print(output)
                    

if __name__ == '__main__':
    sys.exit(main())
