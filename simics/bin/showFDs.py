#!/usr/bin/env python3
#
#    Parse a given system call trace file and report on FD assignments 
#    that are open at a given cycle
#
import sys
import os
import argparse
def getTokenValue(line, token):
    retval = None
    if token in line:
        parts = line.split(token, 1)
        remain = parts[1].strip()
        tparts = remain.split(' ')
        retval = tparts[0].strip()
    return retval

def isBind(line):
    sock_bind = 'return from socketcall bind'
    bind = 'return from bind'
    win_bind = 'return from deviceiocontrolfile'
    if bind.lower() in line or sock_bind.lower() in line.lower() or (win_bind.lower() in line.lower() and 'bind' in line.lower()):
        return True
    else:
        return False

def isConnect(line):
    sock_connect = 'connect tid'
    if (sock_connect in line or 'deviceiocontrolfile connect' in line.lower()) and not 'return from' in line:
        return True
    else:
        return False

def isAccept(line):
    sock_accept = 'return from socketcall accept'
    accept = 'return from accept'
    if 'error' not in line and (accept.lower() in line or sock_accept.lower() in line.lower()):
        return True
    else:
        return False

def isOpen(line):
    from_open = 'from open'
    if (from_open in line): 
        return True
    else:
        return False

def isPipe(line):
    from_pipe = 'from pipe'
    if (from_pipe in line): 
        return True
    else:
        return False

def isClone(line):
    from_clone = 'from clone'
    if (from_clone in line): 
        return True
    else:
        return False

def isDup(line):
    from_dup = 'from dup'
    if (from_dup in line): 
        return True
    else:
        return False

def checkDict(fd_dict, fd, tid):
    # ensure dictionary is initialized for the given fd/tid
    if fd == 'NULL':
        print('checkDict got null fd')
        exit(1)
    if fd not in fd_dict:
        fd_dict[fd] = {}
    if tid not in fd_dict[fd]:
        fd_dict[fd][tid] = {}

def recentCycle(fd_dict, old_fd, tid, new_cycle):
    # find the most recent cycle reported on for the given fd and tid
    recent_cycle = None
    for cycle in fd_dict[old_fd][tid]:
        if cycle > new_cycle:
            break
        else:
            recent_cycle = cycle
    return recent_cycle

def closePipes(fd_dict, tid, fd, cycle):
    # Close any FD (set to None) on the other side of a pipe with the given fd/tid
    fd_list = list(fd_dict.keys())
    for some_fd in fd_list:
        tid_list = list(fd_dict[some_fd].keys())
        for some_tid in tid_list:
            if some_tid == tid:
                continue
            some_recent_cycle = recentCycle(fd_dict, some_fd, some_tid, cycle)
            if some_recent_cycle is not None:
                item = fd_dict[some_fd][some_tid][some_recent_cycle]
                if item is not None:
                    look_for = 'tid:%s : %s' % (tid, fd)
                    if item.endswith(look_for): 
                        #print('0x%x closing pipe fd %s for tid:%s due to close of %s in %s' % (cycle, some_fd, some_tid, fd, tid))
                        fd_dict[some_fd][some_tid][cycle] = None
   

def getDict(trace_file):
    # Parse the trace file and get a dictionary of FD assignments
    fd_dict = {}
    binders = {}
    with open(trace_file) as fh:
        for line in fh:
            tid = getTokenValue(line, 'tid:')
            fd = getTokenValue(line, 'FD:')
            if tid is not None and fd is not None and fd != 'NULL' and fd != 'AT_FD_CWD':
                checkDict(fd_dict, fd, tid)
            if '--' in line:
                dog = line.split('--', 1)[0]
                #print('dog is %s' % dog)
                try:
                    cycle = int(dog, 16)
                except:
                    pass
            if isOpen(line):
                fname = getTokenValue(line, 'file:')
                fd_dict[fd][tid][cycle] = fname
                #if tid == '1186' and fd == '12':
                #    print('dict item %s for fd_dict[%s][%s][0x%x]' % (fname, fd, tid, cycle))
            elif 'from close' in line:
                fd_dict[fd][tid][cycle] = None
                #if tid == '1186' and fd == '12':
                #print('CLOSE dict for fd_dict[%s][%s][0x%x]' % (fd, tid, cycle))
                closePipes(fd_dict, tid, fd, cycle)
            elif isBind(line):
                address = getTokenValue(line, 'address:')
                fd_dict[fd][tid][cycle] = 'bind/%s' % address
                if tid not in binders:
                    binders[tid] = {}
                binders[tid][fd] = address
            elif isAccept(line):
                sock_fd = getTokenValue(line, 'sock_fd:')
                new_fd = getTokenValue(line, 'new_fd:')
                #print('accept tid:%s sock_fd: %s new_fd: %s' % (tid, sock_fd, new_fd))
                if tid in binders and sock_fd in binders[tid]:
                    item = 'accept %s' % binders[tid][fd] 
                else:
                    item = 'accept bound fd: %s' % sock_fd
                checkDict(fd_dict, new_fd, tid)
                fd_dict[new_fd][tid][cycle] = item
                #if tid == '1186' and fd == '12':
                #    print('dict item %s for fd_dict[%s][%s][0x%x]' % (item, fd, tid, cycle))
            elif isPipe(line):
                fd1 = getTokenValue(line, 'fd1')
                fd2 = getTokenValue(line, 'fd2')
                #print('0x%x pipe tid:%s fd1: %s fd2: %s' % (cycle, tid, fd1, fd2))
                checkDict(fd_dict, fd1, tid)
                checkDict(fd_dict, fd2, tid)
                # TBD DO NOT change how these items end, hacky "look_for" depends on it
                fd_dict[fd1][tid][cycle] = 'pipe fd1 for fd2-tid:%s : %s' % (tid, fd2)
                fd_dict[fd2][tid][cycle] = 'pipe fd2 for fd1-tid:%s : %s' % (tid, fd1)
            elif isDup(line):
                old_fd = getTokenValue(line, 'old_fd:')
                new_fd = getTokenValue(line, 'new:')
                if old_fd in fd_dict and tid in fd_dict[old_fd]:
                    recent_cycle = recentCycle(fd_dict, old_fd, tid, cycle)
                    if recent_cycle is not None:
                        checkDict(fd_dict, new_fd, tid)
                        old_item = fd_dict[old_fd][tid][recent_cycle]
                        fd_dict[new_fd][tid][cycle] = old_item
                        #print('0x%x dup tid:%s old_fd: %s new_fd: %s' % (cycle, tid, old_fd, new_fd))
                #print('0x%x dup look for recent cycles that might be pipes for tid:%s old_fd: %s' % (cycle, tid, old_fd))
                # look to see if the duped FD is the other side of a pipe.  We assume the FD will change to the new one
                fd_list = list(fd_dict.keys())
                for some_fd in fd_list:
                    tid_list = list(fd_dict[some_fd].keys())
                    for some_tid in tid_list:
                        if some_tid == tid:
                            continue
                        some_recent_cycle = recentCycle(fd_dict, some_fd, some_tid, cycle)
                        if some_recent_cycle is not None:
                            item = fd_dict[some_fd][some_tid][some_recent_cycle]
                            if item is not None and 'pipe' in item:
                                look_for = 'tid:%s : %s' % (tid, old_fd)
                                if item.endswith(look_for):
                                    new_item = item.replace(old_fd, new_fd)
                                    fd_dict[some_fd][some_tid][cycle] = new_item        
                                    #print('0x%x dup replace item for FD: %s tid:%s with %s' % (cycle, some_fd, some_tid, new_item))
                            # assume new fd will replace old
                        else:
                            #print('\t dup recent cycle for fd: %s tid:%s is None' % (some_fd, some_tid))
                            pass
                               
                 
            elif isClone(line):
                # TBD ug
                new_tid = line.split(':')[-1].strip()
                #print('0x%x got clone of tid:%s to %s' % (cycle, tid, new_tid))
                old_fd_list = list(fd_dict.keys())
                for old_fd in old_fd_list:
                    if old_fd == 'NULL':
                        print('old fd NULL')
                        exit(1)
                    old_tid_list = list(fd_dict[old_fd].keys())
                    for old_tid in old_tid_list:
                        if old_tid == tid:
                            checkDict(fd_dict, old_fd, new_tid) 
                            recent_cycle = recentCycle(fd_dict, old_fd, old_tid, cycle)
                            if recent_cycle is not None:
                                item = fd_dict[old_fd][old_tid][recent_cycle]
                                if item is not None:
                                    if 'pipe' in item:
                                        # set the "other side" to the new tid 
                                        replace_item = item.replace(old_tid, new_tid)
                                        fd_dict[old_fd][old_tid][cycle] = replace_item 
                                        #print('0x%x clone set old fd: %s old_tid:%s to item %s' % (cycle, old_fd, old_tid, replace_item))
                                    fd_dict[old_fd][new_tid][cycle] = item
                                    #print('0x%x clone set old fd: %s new_tid:%s to item %s' % (cycle, old_fd, new_tid, item))
                            else:
                                # likely fd assigned before start of trace
                                #print('failed to get recent cycle for tid:%s FD:%s from cycle 0x%x' % (old_tid, old_fd, cycle))
                                pass
                
    return fd_dict
            
parser = argparse.ArgumentParser(prog='showFDs.py', description='Show FD assignments at a given cycle from a RESim system call trace file')
parser.add_argument('cycle', action='store', help='The cycle (in hex) at which you wish to know the FD assignments.')
parser.add_argument('trace', action='store', help='The name of the trace file')
args = parser.parse_args()
want_cycle = int(args.cycle, 16)
trace_file = args.trace
fd_dict = getDict(trace_file)
print('trace_file %s dict has %d FDs.  These are open at cycle 0x%x:' % (trace_file, len(fd_dict), want_cycle))
for fd in fd_dict:
    #print('dict[%s] has %d tids' % (fd, len(fd_dict[fd])))
    from_cycle = None
    for tid in fd_dict[fd]:
        #print('dict[%s][%s] has %d cycles' % (fd, tid, len(fd_dict[fd][tid])))
        item = None
        for cycle in fd_dict[fd][tid]:
            debug_item = fd_dict[fd][tid][cycle]
            #print('cycle 0x%x want 0x%x debugitem %s' % (cycle, want_cycle, debug_item))
            if cycle < want_cycle:
                item = fd_dict[fd][tid][cycle]
                from_cycle = cycle
            else:
                break
        if item is not None:
            print('\tFD: %s tid:%s is %s set at cycle 0x%x' % (fd, tid, item, from_cycle))



