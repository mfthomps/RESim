''' maintain structure of process hierarchy '''
import pickle
import os
class Pinfo():
    def __init__(self, tid, clone=None, parent=None):
        self.tid = tid
        self.prog = None
        self.args = None
        self.clone = clone
        self.parent = parent
        self.children = []
        self.files = {}
        self.rpipe = {}
        self.wpipe = {}
        ''' dict of lists of FDs for sockets indexed by their address, file name, etc. '''
        self.sockets = {}
        self.ftype = None

class FileWatch():
    def __init__(self, path, outfile):
        self.path = path
        self.outfile = outfile

class TraceProcs():
    def __init__(self, cell_name, context_manager, task_utils, lgr, run_from_snap=None):
        self.lgr = lgr
        self.cell_name = cell_name
        self.context_manager = context_manager
        self.task_utils = task_utils
        ''' dict of Pinfo indexed by tid -- WHICH ARE STRINGS! '''
        self.plist = {}
        self.did_that = []
        self.pipe_handle = {}
        self.socket_handle = {}
        self.latest_tid_instance = {}
        self.init_proc_list = {}
        self.watch_all_exits = False
        self.lgr.debug('traceProcs init')
        ''' init_proc_list is the tid/comm pair read from a checkpoint json
            On display, we'll the entries that do not have children
        '''
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)
            self.lgr.debug('traceProcs init %d tids' % len(self.plist))
        else:
            pass
            #for tid in proc_list:
            #    stid = str(tid)
            #    self.setName(stid, proc_list[tid], None, quiet=False)
            #    self.init_proc_list[stid] = proc_list[tid]

    def loadPickle(self, name):
        proc_file = os.path.join('./', name, self.cell_name, 'traceProcs.pickle')
        if os.path.isfile(proc_file):
            self.lgr.debug('traceProcs %s pickle from %s' % (self.cell_name, proc_file))
            proc_pickle = pickle.load( open(proc_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            self.plist = proc_pickle['plist']
            self.pipe_handle = proc_pickle['pipe_handle']
            self.socket_handle = proc_pickle['socket_handle']
            if 'latest_tid_instance' not in proc_pickle:
                #TBD remove after snapshots updated.
                self.latest_tid_instance = proc_pickle['latest_pid_instance']
            else:
                self.latest_tid_instance = proc_pickle['latest_tid_instance']
            self.init_proc_list = proc_pickle['init_proc_list']
            self.lgr.debug('traceProcs %s loaded %d tids' % (self.cell_name, len(self.plist)))
            

    def pickleit(self, name):
        proc_file = os.path.join('./', name, self.cell_name, 'traceProcs.pickle')
        proc_pickle = {}
        self.cleanProcs()
        proc_pickle['plist'] = self.plist
        proc_pickle['pipe_handle'] = self.pipe_handle
        proc_pickle['socket_handle'] = self.socket_handle
        proc_pickle['latest_tid_instance'] = self.latest_tid_instance
        proc_pickle['init_proc_list'] = self.init_proc_list
        pickle.dump( proc_pickle, open( proc_file, "wb" ) )
        self.lgr.debug('traceProcs pickleit to %s ' % (proc_file))

    def tidExists(self, tid):
        if str(tid) in self.plist:
            return True
        else:
            if tid is not None:
                self.lgr.debug('traceProcs %s not in plist, len of plist is %d' % (tid, len(self.plist)))
            else:
                self.lgr.error('traceProcs given tid is None')
            return False

    def exit(self, tid):
        tid = str(tid)
        self.pipe_handle.pop(tid, None)
        self.socket_handle.pop(tid, None)
        self.lgr.debug('traceProc exit tid %s' % tid)
        entry = self.plist.pop(tid, None)
        if entry is not None:
            if tid not in self.latest_tid_instance:
                self.latest_tid_instance[tid] = 0
            self.latest_tid_instance[tid] += 1
            tidq = '%s-%s' % (tid, self.latest_tid_instance[tid])
            entry.tid = tidq
            self.lgr.debug('traceProc exit tid:%s  tidq %s prog %s' % (tid, tidq, entry.prog))
            ''' find my children and change my name in their records '''
            for ttid in self.plist:
                if self.plist[ttid].parent == tid:
                    self.plist[ttid].parent = tidq
                    self.lgr.debug('traceProcs exit change parent of %s to %s' % (ttid, tidq))
            ''' now find my parent and change name in that record '''
            for ttid in self.plist:
                if tid in self.plist[ttid].children:
                    self.plist[ttid].children.remove(tid) 
                    self.plist[ttid].children.append(tidq)
                    self.lgr.debug('traceProcs exit switched child name of %s from %s to %s' % (ttid, tid, tidq))
            self.plist[tidq] = entry 
        if tid in self.init_proc_list:
           comm = self.init_proc_list.pop(tid, None)
           self.init_proc_list[tidq] = comm
           self.lgr.debug('traceProc exit from proc in initial list tid:%s comm %s' % (tid, comm))

    def getPrecs(self):
        return self.plist

    def nextPipe(self, tid):
        tid = str(tid)
        if tid not in self.pipe_handle:
            self.pipe_handle[tid] = 0 
        self.pipe_handle[tid] = self.pipe_handle[tid]+1
        return self.pipe_handle[tid]

    def nextSocket(self, tid):
        tid = str(tid)
        if tid not in self.socket_handle:
            self.socket_handle[tid] = 0 
        self.socket_handle[tid] = self.socket_handle[tid]+1
        return self.socket_handle[tid]

    def addProc(self, tid, parent, clone=False, comm=None):
        ''' TBD fix this, handle reuse of TIDs'''
        if tid == 0:
            return False
        if tid is None:
            self.lgr.error('traceProcs tid is None')
            return False
        tid = str(tid)
        if parent is not None:
            parent = str(parent)
        if tid in self.plist:      
            ''' edge case of snapshot created during execve '''
            if tid not in self.init_proc_list:
                self.lgr.debug('traceProc addProc, tid:%s already in plist parent: %s' % (tid, parent))
            return False
        self.lgr.debug('traceProc addProc tid:%s  parent %s  plist now %d' % (tid, parent, len(self.plist)))
        if parent is not None:
            if parent not in self.plist:
                self.lgr.debug('No parent %s yet for tid:%s, add it.' % (parent, tid)) 
                parent_pinfo = Pinfo(parent)
                self.plist[parent] = parent_pinfo 
            self.plist[parent].children.append(tid)
        newproc = Pinfo(tid, clone=clone, parent=parent)
        self.plist[tid] = newproc 
        #self.lgr.debug('procTrace addProc tid:%s parent:%s clone: %r comm: %s' % (tid, parent, clone, comm))
        if clone:
            if parent is not None and self.plist[parent].prog is not None:
                self.plist[tid].prog = '%s' % self.plist[parent].prog
                #self.lgr.debug('procTrace addProc plist[%s].prog set to %s' % (tid, self.plist[parent].prog))
            else:
                #self.lgr.debug('procTrace addProc plist[%s].prog set to <clone>' % (tid))
                self.plist[tid].prog = '<clone>'
        elif comm is not None:  
            self.plist[tid].prog = comm
        if self.watch_all_exits:
            self.context_manager.watchExit(tid = tid)
        return True

    def setName(self, tid, prog, args, quiet=True):
        tid = str(tid)
        if tid not in self.plist:
            if not quiet:
                self.lgr.debug('TraceProcs, setName, no tid yet %s, add it' % tid)
            newproc = Pinfo(tid)
            self.plist[tid] = newproc
        if not quiet:
            self.lgr.debug('TraceProcs, setName, tid:%s, to %s' % (tid, prog))
        self.plist[tid].prog = prog        
        self.plist[tid].args = args        
   

    def open(self, tid, comm, filename, fd):
        tid = str(tid)
        if tid not in self.plist:
            self.lgr.debug('TraceProcs open no tid:%s, add it ' % tid)
            newproc = Pinfo(tid)
            newproc.prog = comm
            self.plist[tid] = newproc
        if filename in self.plist[tid].files:
            #self.lgr.debug('traceProcs open append fd %d to file %s for tid %s' % (fd, filename, tid))
            self.plist[tid].files[filename].append(fd)
        else:
            #self.lgr.debug('traceProcs open first fd %d to file %s for tid %s' % (fd, filename, tid))
            self.plist[tid].files[filename] = [fd]

    def pipe(self, tid, fd1, fd2):
        tid = str(tid)
        pname = 'pipe-%s-%s' % (tid, self.nextPipe(tid))
        if tid not in self.plist:
            self.lgr.debug('TraceProcs pipe no tid:%s, add it ' % tid)
            newproc = Pinfo(tid)
            self.plist[tid] = newproc
        self.plist[tid].rpipe[pname] = [fd1]
        self.plist[tid].wpipe[pname] = [fd2]

    def socket(self, tid, fd):
        tid = str(tid)
        sname = 'socket-%s-%s' % (tid, self.nextSocket(tid))
        if tid not in self.plist:
            self.lgr.debug('TraceProcs socket no tid:%s, add it ' % tid)
            newproc = Pinfo(tid)
            self.plist[tid] = newproc
        self.plist[tid].sockets[sname] = [fd]

    def connect(self, tid, fd, name):
        tid = str(tid)
        if tid not in self.plist:
            self.lgr.debug('TraceProcs connect no tid:%s' % tid)
            return
        gotit = None
        for s in self.plist[tid].sockets:
            if fd in self.plist[tid].sockets[s]:
                gotit = s
                break
        if gotit is not None:
            self.plist[tid].sockets[name] = list(self.plist[tid].sockets[gotit])
            del self.plist[tid].sockets[gotit] 
        else:
            ''' assume we did not record the socket call '''
            self.lgr.debug('TraceProcs, connect tid %s, could not find fd %d' % (tid, fd))
            self.plist[tid].sockets[name] = [fd]

    def socketpair(self, tid, fd1, fd2):
        tid = str(tid)
        sname = 'socket-%s-%s' % (tid, self.nextSocket(tid))
        if tid not in self.plist:
            self.lgr.debug('TraceProcs socketpair no tid %s, add it ' % tid)
            newproc = Pinfo(tid)
            self.plist[tid] = newproc
        self.plist[tid].sockets[sname] = [fd1, fd2]

    def isExternal(self, tid, fd):
        if tid in self.plist:
            for s in self.plist[tid].sockets:
                if fd in self.plist[tid].sockets[s]:
                    if ':' in s:
                        return True
        return False
    
    def bind(self, tid, fd, name):
        tid = str(tid)
        if tid not in self.plist:
            self.lgr.debug('TraceProcs connect no tid %s' % tid)
            return
        ''' socket call got the FD, associate a meaningful name '''
        gotit = None
        for s in self.plist[tid].sockets:
            if fd in self.plist[tid].sockets[s]:
                gotit = s
                break
        if gotit is not None:
            ''' replace the dict entry with the more meaningful name '''
            self.plist[tid].sockets[name] = list(self.plist[tid].sockets[gotit])
            del self.plist[tid].sockets[gotit] 
        else:
            ''' assume we did not record the socket call '''
            self.lgr.debug('TraceProcs, bind tid %s, could not find fd %d' % (tid, fd))
            self.plist[tid].sockets[name] = [fd]

    def accept(self, tid, socket_fd, new_fd, name):
        tid = str(tid)
        if tid not in self.plist:
            self.lgr.debug('TraceProcs accept no tid %s' % tid)
            return
        if name is None:
            for s in self.plist[tid].sockets:
                if socket_fd in self.plist[tid].sockets[s]:
                    self.plist[tid].sockets[s].append(new_fd)
                    break
        else:
            self.plist[tid].sockets[name] = [new_fd]
        

    def rmFD(self, tid, fd):
        tid = str(tid)
        for fname in self.plist[tid].files: 
            if fd in self.plist[tid].files[fname]:
                #self.lgr.debug('GOT close tid %s fd %d file %s' % (tid, fd, fname))
                self.plist[tid].files[fname].remove(fd)
                return
        for pname in self.plist[tid].rpipe: 
            if fd in self.plist[tid].rpipe[pname]:
                #self.lgr.debug('GOT close tid %s fd %d file %s' % (tid, fd, pname))
                self.plist[tid].rpipe[pname].remove(fd)
                return
        for pname in self.plist[tid].wpipe: 
            if fd in self.plist[tid].wpipe[pname]:
                #self.lgr.debug('GOT close tid %s fd %d file %s' % (tid, fd, pname))
                self.plist[tid].wpipe[pname].remove(fd)
                return
        for sname in self.plist[tid].sockets: 
            if fd in self.plist[tid].sockets[sname]:
                #self.lgr.debug('GOT close tid %s fd %d file %s' % (tid, fd, sname))
                self.plist[tid].sockets[sname].remove(fd)
                return

    def close(self, tid, fd):
        tid = str(tid)
        if tid not in self.plist:
            #self.lgr.debug('traceProcs close on unknown tid %s' % tid)
            return
        #self.lgr.debug('try close tid %s fd %d' % (tid, fd))
        self.rmFD(tid, fd)

    def dup(self, tid, fd_old, fd_new):
        tid = str(tid)
        if tid not in self.plist:
            self.lgr.debug('traceProcs dup on unknown tid %s' % tid)
            return

        ''' close any file/pipe/socket having the new fd '''
        self.rmFD(tid, fd_new) 

        for fname in self.plist[tid].files:
            if fd_old in self.plist[tid].files[fname]:
                self.plist[tid].files[fname].append(fd_new)
                return
        for pname in self.plist[tid].rpipe:
            if fd_old in self.plist[tid].rpipe[pname]:
                self.plist[tid].rpipe[pname].append(fd_new)
                return
        for pname in self.plist[tid].wpipe:
            if fd_old in self.plist[tid].wpipe[pname]:
                self.plist[tid].wpipe[pname].append(fd_new)
                return

        self.lgr.debug('traceProcs, dup tid %s, did not find file with old fd of %d' % (tid, fd_old)) 
        fname = 'unknown-%s-%d' % (tid, fd_old)
        self.plist[tid].files[fname] = [fd_old, fd_new]

    def copyOpen(self, parent_tid, child_tid):
        parent_tid = str(parent_tid)
        child_tid = str(child_tid)
        if parent_tid not in self.plist:
            self.lgr.debug('traceProcs copyOpen on unknown tid %s' % parent_tid)
            return
        if child_tid not in self.plist[parent_tid].children:
            self.plist[parent_tid].children.append(child_tid)
        self.plist[child_tid].parent = child_tid
        for fname in self.plist[parent_tid].files:
            self.plist[child_tid].files[fname] = []
            for fd in self.plist[parent_tid].files[fname]:
                self.plist[child_tid].files[fname].append(fd)
                #self.lgr.debug('traceProcs copyOpen file %s from %s to %s fd: %d' % (fname, parent_tid, child_tid, fd))
            #if len(self.plist[parent_tid].files[fname]) > 0:
            #    self.lgr.debug('traceProcs copyOpen file %s from %s to %s' % (fname, parent_tid, child_tid))
            #    self.plist[child_tid].files[fname] = list(self.plist[parent_tid].files[fname])
        for pname in self.plist[parent_tid].rpipe:
            if len(self.plist[parent_tid].rpipe[pname]) > 0:
                #self.lgr.debug('traceProcs copyOpen from %s to %s' % (parent_tid, child_tid))
                self.plist[child_tid].rpipe[pname] = list(self.plist[parent_tid].rpipe[pname])
        for pname in self.plist[parent_tid].wpipe:
            if len(self.plist[parent_tid].wpipe[pname]) > 0:
                #self.lgr.debug('traceProcs copyOpen from %s to %s' % (parent_tid, child_tid))
                self.plist[child_tid].wpipe[pname] = list(self.plist[parent_tid].wpipe[pname])
        for sname in self.plist[parent_tid].sockets:
            if len(self.plist[parent_tid].sockets[sname]) > 0:
                #self.lgr.debug('traceProcs copyOpen from %s to %s' % (parent_tid, child_tid))
                self.plist[child_tid].sockets[sname] = list(self.plist[parent_tid].sockets[sname])
  
    def showOne(self, tid, tabs):
        tid = str(tid)
        files = ''
        sockets = ''
        pipes = ''
        if tid not in self.plist:
            print('tid %s not in plist' % tid)
            return
        for f in self.plist[tid].files:
            if len(self.plist[tid].files[f]) > 0:
                files = files + ' %s(%s)' % (f, str(self.plist[tid].files[f]))
            else:
                files = files + ' %s' % (f)

        for p in self.plist[tid].rpipe:
            if len(self.plist[tid].rpipe[p]) > 0:
                pipes = pipes + ' %s(R%s)' % (p, str(self.plist[tid].rpipe[p]))
            else:
                pipes = pipes + ' %s' % (p)
        for p in self.plist[tid].wpipe:
            if len(self.plist[tid].wpipe[p]) > 0:
                pipes = pipes + ' %s(W%s)' % (p, str(self.plist[tid].wpipe[p]))
            else:
                pipes = pipes + ' %s' % (p)
        for s in self.plist[tid].sockets:
            if len(self.plist[tid].sockets[s]) > 0:
                sockets = sockets + ' %s(S%s)' % (s, str(self.plist[tid].sockets[s]))
            else:
                #sockets = sockets + ' %s' % (s)
                pass

        ftype = ''
        if self.plist[tid].ftype is not None:
            ftype = 'file type: '+self.plist[tid].ftype
        if self.plist[tid].args is None:
            self.trace_fh.write('%s %s  %s %s\n' % (tabs, tid, self.plist[tid].prog, ftype))
            print('%s %s  %s' % (tabs, tid, self.plist[tid].prog))
        else:
            self.trace_fh.write('%s %s  %s %s %s\n' % (tabs, tid, self.plist[tid].prog, self.plist[tid].args, ftype)) 
            print('%s %s  %s %s' % (tabs, tid, self.plist[tid].prog, self.plist[tid].args)) 

        if len(files) > 0:
            print('%s    files: %s\n' % (tabs, files))
            self.trace_fh.write('%s    files: %s\n' % (tabs, files))
        if len(pipes) > 0:
            print('%s    pipes: %s' % (tabs, pipes))
            self.trace_fh.write('%s    pipes: %s\n' % (tabs, pipes))
        if len(sockets) > 0:
            print('%s    sockets: %s' % (tabs, sockets))
            self.trace_fh.write('%s    sockets: %s\n' % (tabs, sockets))

    def showFamily(self, tid, tabs):
        tid = str(tid)
        #self.lgr.debug('traceProcs showFamily tid:<%s> type %s' % (tid, type(tid)))
        self.showOne(tid, tabs)
        if tid not in self.did_that:
            self.did_that.append(tid)
        tabs = tabs+'\t'
        if tid in self.plist:
            for child in self.plist[tid].children:
                self.showFamily(child, tabs)

    def showAll(self, quiet=False):
        trace_path = '/tmp/procTrace.txt'
        self.trace_fh = open(trace_path, 'w') 
        del self.did_that[:]
        for tid in self.plist:
            if self.plist[tid].parent is not None:
                #self.lgr.debug('traceProcs showAll parent is %s, skip' % self.plist[tid].parent)
                continue
            ''' ignore items from initial set of processes that did not subsequently create children '''
            if tid in self.init_proc_list and len(self.plist[tid].children) == 0:
                continue
            if tid not in self.did_that:
                self.did_that.append(tid)
                tabs = ''
                #self.lgr.debug('traceProcs showAll showFamily for %s' % tid)
                self.showFamily(tid, tabs)                
        self.getNetworkAddresses()
        self.trace_fh.close()
        print('Trace report at: %s' % trace_path)
                 
    def getProg(self, tid):
        tid = str(tid)
        if tid in self.plist: 
            return self.plist[tid].prog
        else:
            return 'unknown'

    def getNetworkAddresses(self):
        for tid in self.plist:
            info = self.plist[tid].args
            if info is not None and '/bin/ip addr add' in info:
                print(info)

    def getFileName(self, tid, fd):
        tid = str(tid)
        if tid in self.plist:
            for f in self.plist[tid].files:
                self.lgr.debug('traceProcs tid %s look for file for fd %d file %s' % (tid, fd, f))
                if fd in self.plist[tid].files[f]:
                    return f
        return None

    def setFileType(self, tid, ftype):
        tid = str(tid)
        if 'elf' in ftype.lower():
            self.plist[tid].ftype = 'elf'
        elif 'shell' in ftype.lower(): 
            self.plist[tid].ftype = 'shell'
        else:
            self.lgr.debug('traceProcs tid:%s unknown file type %s' % (tid, ftype))
        self.lgr.debug('traceProcs setFileType tid:%s file type %s' % (tid, self.plist[tid].ftype))

    def getFileType(self, tid):
        tid = str(tid)
        if tid in self.plist:
            return self.plist[tid].ftype
        else:
            return None

    def watchAllExits(self):
        self.lgr.debug('traceProcs watchAllExits for %d tids' % len(self.plist))
        self.cleanProcs()
        for tid in self.plist:
            self.context_manager.watchExit(tid=tid)
        self.watch_all_exits = True

    def cleanProcs(self):
        tid_list = self.task_utils.getTidList()
        self.lgr.debug('traceProcs cleanProcs start with %d tids, task utils gave %d' % (len(self.plist), len(tid_list)))
        tmp_list = list(self.plist.keys())
        for p in tmp_list:
            if p not in tid_list:
                self.plist.pop(p, None)
        self.lgr.debug('traceProcs cleanProcs end with %d tids' % len(self.plist))
      
                
