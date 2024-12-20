#!/usr/bin/env python3
#
#    Parse a given system call trace file and report on FD assignments 
#    that are open at a given cycle
#
import sys
import os
import argparse
class FDTrack():
    def __init__(self):
        self.fd_dict = {}
        self.recent_cycle = {}

    def setItem(self, fd, tid, cycle, item):
        self.checkDict(fd, tid)
        self.fd_dict[fd][tid][cycle] = item
        self.recent_cycle[fd][tid] = cycle

    def getItem(self, fd, tid, cycle):
        if fd in self.fd_dict and tid in self.fd_dict[fd] and cycle in self.fd_dict[fd][tid]:
            return self.fd_dict[fd][tid][cycle]
        else:
            print('ERROR failed to get item for fd: %s tid:%s cycle 0x%x' % (fd, tid, cycle))
            return None 

    def checkDict(self, fd, tid):
        # ensure dictionary is initialized for the given fd/tid
        if fd == 'NULL':
            print('checkDict got null fd')
            exit(1)
        if fd not in self.fd_dict:
            self.fd_dict[fd] = {}
        if tid not in self.fd_dict[fd]:
            self.fd_dict[fd][tid] = {}
        if fd not in self.recent_cycle:
            self.recent_cycle[fd] = {}

    def recentCycle(self, fd, tid):
        if fd in self.recent_cycle and tid in self.recent_cycle[fd]:
            return self.recent_cycle[fd][tid]
        else:
            return None
         
    def getRecent(self, fd, tid):
        if fd in self.fd_dict and tid in self.fd_dict[fd]:
            return self.fd_dict[fd][tid]
        else:
            return None

    def getFDList(self):
        fd_list = list(self.fd_dict.keys())
        return fd_list

    def getTidList(self, fd):
        tid_list = list(self.fd_dict[fd].keys())
        return tid_list

    def hasFDTid(self, fd, tid):
        if fd in self.fd_dict and tid in self.fd_dict[fd]:
            return True
        else:
            return False

    def show(self):
        print('trace_file %s dict has %d FDs.  These are open at cycle 0x%x:' % (trace_file, len(self.fd_dict), want_cycle))
        for fd in self.fd_dict:
            #print('dict[%s] has %d tids' % (fd, len(self.fd_dict[fd])))
            from_cycle = None
            for tid in self.fd_dict[fd]:
                #print('dict[%s][%s] has %d cycles' % (fd, tid, len(self.fd_dict[fd][tid])))
                item = None
                for cycle in self.fd_dict[fd][tid]:
                    debug_item = self.fd_dict[fd][tid][cycle]
                    #print('cycle 0x%x want 0x%x debugitem %s' % (cycle, want_cycle, debug_item))
                    if cycle < want_cycle:
                        item = self.fd_dict[fd][tid][cycle]
                        from_cycle = cycle
                    else:
                        break
                if item is not None:
                    print('\tFD: %s tid:%s is %s set at cycle 0x%x' % (fd, tid, item, from_cycle))

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
    if (sock_connect in line or 'deviceiocontrolfile connect' in line.lower()) and 'return from' in line:
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


def closePipes(fd_track, tid, fd, cycle):
    # Close any FD (set to None) on the other side of a pipe with the given fd/tid
    fd_list = fd_track.getFDList()
    for some_fd in fd_list:
        tid_list = fd_track.getTidList(some_fd)
        for some_tid in tid_list:
            if some_tid == tid:
                continue
            some_recent_cycle = fd_track.recentCycle(some_fd, some_tid)
            if some_recent_cycle is not None:
                item = fd_track.getItem(some_fd, some_tid, some_recent_cycle)
                #item = fd_dict[some_fd][some_tid][some_recent_cycle]
                if item is not None:
                    look_for = 'tid:%s : %s' % (tid, fd)
                    if item.endswith(look_for): 
                        #print('0x%x closing pipe fd %s for tid:%s due to close of %s in %s' % (cycle, some_fd, some_tid, fd, tid))
                        fd_track.setItem(some_fd, some_tid, cycle, None)
   

def getDict(trace_file):
    # Parse the trace file and get a dictionary of FD assignments
    fd_track = FDTrack()
    binders = {}
    with open(trace_file) as fh:
        for line in fh:
            tid = getTokenValue(line, 'tid:')
            fd = getTokenValue(line, 'FD:')
            if fd is not None and fd.startswith('-'):
                continue
            if '--' in line:
                dog = line.split('--', 1)[0]
                #print('dog is %s' % dog)
                try:
                    cycle = int(dog, 16)
                except:
                    pass
            if isOpen(line):
                fname = getTokenValue(line, 'file:')
                fd_track.setItem(fd, tid, cycle, fname)
            elif 'from close' in line:
                fd_track.setItem(fd, tid, cycle, None)
                closePipes(fd_track, tid, fd, cycle)
            elif isBind(line):
                address = getTokenValue(line, 'address:')
                item = 'bind/%s' % address
                fd_track.setItem(fd, tid, cycle, item)
                if tid not in binders:
                    binders[tid] = {}
                binders[tid][fd] = address
            elif isConnect(line):
                address = getTokenValue(line, 'sa_data:')
                item = 'connect %s' % address
                fd_track.setItem(fd, tid, cycle, item)
            elif isAccept(line):
                sock_fd = getTokenValue(line, 'sock_fd:')
                new_fd = getTokenValue(line, 'new_fd:')
                #print('accept tid:%s sock_fd: %s new_fd: %s' % (tid, sock_fd, new_fd))
                if tid in binders and sock_fd in binders[tid]:
                    item = 'accept %s' % binders[tid][fd] 
                else:
                    item = 'accept bound fd: %s' % sock_fd
                fd_track.setItem(new_fd, tid, cycle, item)
            elif isPipe(line):
                fd1 = getTokenValue(line, 'fd1')
                fd2 = getTokenValue(line, 'fd2')
                #print('0x%x pipe tid:%s fd1: %s fd2: %s' % (cycle, tid, fd1, fd2))
                # TBD DO NOT change how these items end, hacky "look_for" depends on it
                item = 'pipe fd1 for fd2-tid:%s : %s' % (tid, fd2)
                fd_track.setItem(fd1, tid, cycle, item)
                item = 'pipe fd2 for fd1-tid:%s : %s' % (tid, fd1)
                fd_track.setItem(fd2, tid, cycle, item)
            elif isDup(line):
                old_fd = getTokenValue(line, 'old_fd:')
                new_fd = getTokenValue(line, 'new:')
                if fd_track.hasFDTid(old_fd, tid):
                    recent_cycle = fd_track.recentCycle(old_fd, tid)
                    if recent_cycle is not None:
                        old_item = fd_track.getItem(old_fd, tid, recent_cycle)
                        fd_track.setItem(new_fd, tid, cycle, old_item)
                        #print('0x%x dup tid:%s old_fd: %s new_fd: %s' % (cycle, tid, old_fd, new_fd))
                #print('0x%x dup look for recent cycles that might be pipes for tid:%s old_fd: %s' % (cycle, tid, old_fd))
                # look to see if the duped FD is the other side of a pipe.  We assume the FD will change to the new one
                fd_list = fd_track.getFDList()
                for some_fd in fd_list:
                    tid_list = fd_track.getTidList(some_fd)
                    for some_tid in tid_list:
                        if some_tid == tid:
                            continue
                        some_recent_cycle = fd_track.recentCycle(some_fd, some_tid)
                        if some_recent_cycle is not None:
                            item = fd_track.getItem(some_fd, some_tid, some_recent_cycle)
                            if item is not None and 'pipe' in item:
                                look_for = 'tid:%s : %s' % (tid, old_fd)
                                if item.endswith(look_for):
                                    new_end = 'tid:%s : %s' % (tid, new_fd)
                                    new_item = item.replace(look_for, new_end)
                                    fd_track.setItem(some_fd, some_tid, cycle, new_item)
                            # assume new fd will replace old
                        else:
                            #print('\t dup recent cycle for fd: %s tid:%s is None' % (some_fd, some_tid))
                            pass
                               
                 
            elif isClone(line):
                # TBD ug
                new_tid = line.split(':')[-1].strip()
                if new_tid.startswith('-'):
                    continue
                #print('0x%x got clone of tid:%s to %s' % (cycle, tid, new_tid))
                old_fd_list = fd_track.getFDList()
                for old_fd in old_fd_list:
                    if old_fd == 'NULL':
                        print('old fd NULL')
                        exit(1)
                    old_tid_list = fd_track.getTidList(old_fd)
                    for old_tid in old_tid_list:
                        if old_tid == tid:
                            #print('\t tid:%s check recent cycle for old_fd: %s' % (tid, old_fd))
                            recent_cycle = fd_track.recentCycle(old_fd, old_tid)
                            if recent_cycle is not None:
                                item = fd_track.getItem(old_fd, old_tid, recent_cycle)
                                #print('\t got item %s recent cycle 0x%x' % (item, recent_cycle))
                                if item is not None:
                                    if 'pipe' in item:
                                        # set the "other side" to the new tid 
                                        old_str = 'tid:%s ' % old_tid
                                        new_str = 'tid:%s ' % new_tid
                                        replace_item = item.replace(old_str, new_str)
                                        fd_track.setItem(old_fd, old_tid, cycle, replace_item)
                                        #print('0x%x clone set old fd: %s old_tid:%s to item %s old_item: %s' % (cycle, old_fd, old_tid, replace_item, item))
                                        if len(new_str) > 9:
                                            exit(1)
                                    fd_track.setItem(old_fd, new_tid, cycle, item)
                                    #print('0x%x clone set old fd: %s new_tid:%s to item %s' % (cycle, old_fd, new_tid, item))
                            else:
                                # likely fd assigned before start of trace
                                #print('failed to get recent cycle for tid:%s FD:%s from cycle 0x%x' % (old_tid, old_fd, cycle))
                                pass
            elif 'exit_group' in line:
                fd_list = fd_track.getFDList()
                for old_fd in fd_list:
                    tid_list = fd_track.getTidList(old_fd)
                    if tid in tid_list:
                        fd_track.setItem(old_fd, tid, cycle, None)
                        closePipes(fd_track, tid, old_fd, cycle)
                
    return fd_track
            
parser = argparse.ArgumentParser(prog='showFDs.py', description='Show FD assignments at a given cycle from a RESim system call trace file')
parser.add_argument('cycle', action='store', help='The cycle (in hex) at which you wish to know the FD assignments.')
parser.add_argument('trace', action='store', help='The name of the trace file')
args = parser.parse_args()
want_cycle = int(args.cycle, 16)
trace_file = args.trace
fd_track = getDict(trace_file)
fd_track.show()



