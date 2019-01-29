''' maintain structure of process hierarchy '''
class Pinfo():
    def __init__(self, pid, clone=None, parent=None):
        self.pid = pid
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

class TraceProcs():
    def __init__(self, lgr, proc_list):
        self.lgr = lgr
        ''' dict of Pinfo indexed by pid '''
        self.plist = {}
        self.did_that = []
        self.trace_fh = None
        self.pipe_handle = {}
        self.socket_handle = {}
        self.latest_pid_instance = {}
        ''' init_proc_list is the pid/comm pair read from a checkpoint json
            On display, we'll the entries that do not have children
        '''
        self.init_proc_list = {}
        for pid in proc_list:
            self.setName(pid, proc_list[pid], None, quiet=True)
            self.init_proc_list[str(pid)] = proc_list[pid]

    def pidExists(self, pid):
        if str(pid) in self.plist:
            return True
        else:
            return False

    def exit(self, pid):
        pid = str(pid)
        self.pipe_handle.pop(pid, None)
        self.socket_handle.pop(pid, None)
        entry = self.plist.pop(pid, None)
        if entry is not None:
            if pid not in self.latest_pid_instance:
                self.latest_pid_instance[pid] = 0
            self.latest_pid_instance[pid] += 1
            pidq = '%s-%d' % (pid, self.latest_pid_instance[pid])
            entry.pid = pidq
            self.lgr.debug('traceProc exit pid:%s  pidq %s prog %s' % (pid, pidq, entry.prog))
            ''' find my children and change my name in their records '''
            for tpid in self.plist:
                if self.plist[tpid].parent == pid:
                    self.plist[tpid].parent = pidq
            ''' now find my parent and change name in that record '''
            for tpid in self.plist:
                if pid in self.plist[tpid].children:
                    self.plist[tpid].children.remove(pid) 
                    self.plist[tpid].children.append(pidq)
            self.plist[pidq] = entry 
        if pid in self.init_proc_list:
           comm = self.init_proc_list.pop(pid, None)
           self.init_proc_list[pidq] = comm
           self.lgr.debug('traceProc exit from proc in initial list comm %s' % comm)

    def getPrecs(self):
        return self.plist

    def nextPipe(self, pid):
        pid = str(pid)
        if pid not in self.pipe_handle:
            self.pipe_handle[pid] = 0 
        self.pipe_handle[pid] = self.pipe_handle[pid]+1
        return self.pipe_handle[pid]

    def nextSocket(self, pid):
        pid = str(pid)
        if pid not in self.socket_handle:
            self.socket_handle[pid] = 0 
        self.socket_handle[pid] = self.socket_handle[pid]+1
        return self.socket_handle[pid]

    def addProc(self, pid, parent, clone=False):
        pid = str(pid)
        parent = str(parent)
        if pid in self.plist:      
            self.lgr.error('addProc, pid:%s already in plist parent: %s' % (pid, parent))
            return False
        self.lgr.debug('traceProc addProc pid:%s  parent %s' % (pid, parent))
        if parent not in self.plist:
            self.lgr.debug('No parent %s yet for pid:%s, add it.' % (parent, pid)) 
            parent_pinfo = Pinfo(parent)
            self.plist[parent] = parent_pinfo 
        self.plist[parent].children.append(pid)
        newproc = Pinfo(pid, clone=clone, parent=parent)
        self.plist[pid] = newproc 
        if clone:
            if self.plist[parent].prog is not None:
                self.plist[pid].prog = '%s <clone>' % self.plist[parent].prog
            else:
                self.plist[pid].prog = '<clone>'
        return True

    def setName(self, pid, prog, args, quiet=False):
        pid = str(pid)
        if pid not in self.plist:
            if not quiet:
                self.lgr.debug('TraceProcs, setName, no pid yet %s, add it' % pid)
            newproc = Pinfo(pid)
            self.plist[pid] = newproc
        if not quiet:
            self.lgr.debug('TraceProcs, setName, pid:%s, to %s' % (pid, prog))
        self.plist[pid].prog = prog        
        self.plist[pid].args = args        
   

    def open(self, pid, comm, filename, fd):
        pid = str(pid)
        if pid not in self.plist:
            self.lgr.debug('TraceProcs open no pid:%s, add it ' % pid)
            newproc = Pinfo(pid)
            newproc.prog = comm
            self.plist[pid] = newproc
        self.plist[pid].files[filename] = [fd]

    def pipe(self, pid, fd1, fd2):
        pid = str(pid)
        pname = 'pipe-%s-%d' % (pid, self.nextPipe(pid))
        if pid not in self.plist:
            self.lgr.debug('TraceProcs pipe no pid:%s, add it ' % pid)
            newproc = Pinfo(pid)
            self.plist[pid] = newproc
        self.plist[pid].rpipe[pname] = [fd1]
        self.plist[pid].wpipe[pname] = [fd2]

    def socket(self, pid, fd):
        pid = str(pid)
        sname = 'socket-%s-%d' % (pid, self.nextSocket(pid))
        if pid not in self.plist:
            self.lgr.debug('TraceProcs socket no pid:%s, add it ' % pid)
            newproc = Pinfo(pid)
            self.plist[pid] = newproc
        self.plist[pid].sockets[sname] = [fd]

    def connect(self, pid, fd, name):
        pid = str(pid)
        if pid not in self.plist:
            self.lgr.debug('TraceProcs connect no pid:%s' % pid)
            return
        gotit = None
        for s in self.plist[pid].sockets:
            if fd in self.plist[pid].sockets[s]:
                gotit = s
                break
        if gotit is not None:
            self.plist[pid].sockets[name] = list(self.plist[pid].sockets[gotit])
            del self.plist[pid].sockets[gotit] 
        else:
            ''' assume we did not record the socket call '''
            self.lgr.debug('TraceProcs, connect pid %s, could not find fd %d' % (pid, fd))
            self.plist[pid].sockets[name] = [fd]

    def socketpair(self, pid, fd1, fd2):
        pid = str(pid)
        sname = 'socket-%s-%d' % (pid, self.nextSocket(pid))
        if pid not in self.plist:
            self.lgr.debug('TraceProcs socketpair no pid %s, add it ' % pid)
            newproc = Pinfo(pid)
            self.plist[pid] = newproc
        self.plist[pid].sockets[sname] = [fd1, fd2]

    def bind(self, pid, fd, name):
        pid = str(pid)
        if pid not in self.plist:
            self.lgr.debug('TraceProcs connect no pid %s' % pid)
            return
        ''' socket call got the FD, associate a meaningful name '''
        gotit = None
        for s in self.plist[pid].sockets:
            if fd in self.plist[pid].sockets[s]:
                gotit = s
                break
        if gotit is not None:
            ''' replace the dict entry with the more meaningful name '''
            self.plist[pid].sockets[name] = list(self.plist[pid].sockets[gotit])
            del self.plist[pid].sockets[gotit] 
        else:
            ''' assume we did not record the socket call '''
            self.lgr.debug('TraceProcs, bind pid %s, could not find fd %d' % (pid, fd))
            self.plist[pid].sockets[name] = [fd]

    def accept(self, pid, socket_fd, new_fd, name):
        pid = str(pid)
        if pid not in self.plist:
            self.lgr.debug('TraceProcs accept no pid %s' % pid)
            return
        if name is None:
            for s in self.plist[pid].sockets:
                if socket_fd in self.plist[pid].sockets[s]:
                    self.plist[pid].sockets[s].append(new_fd)
                    break
        else:
            self.plist[pid].sockets[name] = [new_fd]
        

    def rmFD(self, pid, fd):
        pid = str(pid)
        for fname in self.plist[pid].files: 
            if fd in self.plist[pid].files[fname]:
                #self.lgr.debug('GOT close pid %d fd %d file %s' % (pid, fd, fname))
                self.plist[pid].files[fname].remove(fd)
                return
        for pname in self.plist[pid].rpipe: 
            if fd in self.plist[pid].rpipe[pname]:
                #self.lgr.debug('GOT close pid %d fd %d file %s' % (pid, fd, pname))
                self.plist[pid].rpipe[pname].remove(fd)
                return
        for pname in self.plist[pid].wpipe: 
            if fd in self.plist[pid].wpipe[pname]:
                #self.lgr.debug('GOT close pid %d fd %d file %s' % (pid, fd, pname))
                self.plist[pid].wpipe[pname].remove(fd)
                return
        for sname in self.plist[pid].sockets: 
            if fd in self.plist[pid].sockets[sname]:
                #self.lgr.debug('GOT close pid %d fd %d file %s' % (pid, fd, sname))
                self.plist[pid].sockets[sname].remove(fd)
                return

    def close(self, pid, fd):
        pid = str(pid)
        if pid not in self.plist:
            #self.lgr.debug('traceProcs close on unknown pid %d' % pid)
            return
        #self.lgr.debug('try close pid %d fd %d' % (pid, fd))
        self.rmFD(pid, fd)

    def dup(self, pid, fd_old, fd_new):
        pid = str(pid)
        if pid not in self.plist:
            self.lgr.debug('traceProcs dup on unknown pid %s' % pid)
            return

        ''' close any file/pipe/socket having the new fd '''
        self.rmFD(pid, fd_new) 

        for fname in self.plist[pid].files:
            if fd_old in self.plist[pid].files[fname]:
                self.plist[pid].files[fname].append(fd_new)
                return
        for pname in self.plist[pid].rpipe:
            if fd_old in self.plist[pid].rpipe[pname]:
                self.plist[pid].rpipe[pname].append(fd_new)
                return
        for pname in self.plist[pid].wpipe:
            if fd_old in self.plist[pid].wpipe[pname]:
                self.plist[pid].wpipe[pname].append(fd_new)
                return

        self.lgr.debug('traceProcs, dup pid %s, did not find file with old fd of %d' % (pid, fd_old)) 
        fname = 'unknown-%s-%d' % (pid, fd_old)
        self.plist[pid].files[fname] = [fd_old, fd_new]

    def copyOpen(self, parent_pid, child_pid):
        parent_pid = str(parent_pid)
        child_pid = str(child_pid)
        if parent_pid not in self.plist:
            self.lgr.debug('traceProcs copyOpen on unknown pid %s' % parent_pid)
            return
        if child_pid not in self.plist[parent_pid].children:
            self.plist[parent_pid].children.append(child_pid)
        self.plist[child_pid].parent = child_pid
        for fname in self.plist[parent_pid].files:
            if len(self.plist[parent_pid].files[fname]) > 0:
                #self.lgr.debug('traceProcs copyOpen from %s to %s' % (parent_pid, child_pid))
                self.plist[child_pid].files[fname] = list(self.plist[parent_pid].files[fname])
        for pname in self.plist[parent_pid].rpipe:
            if len(self.plist[parent_pid].rpipe[pname]) > 0:
                #self.lgr.debug('traceProcs copyOpen from %s to %s' % (parent_pid, child_pid))
                self.plist[child_pid].rpipe[pname] = list(self.plist[parent_pid].rpipe[pname])
        for pname in self.plist[parent_pid].wpipe:
            if len(self.plist[parent_pid].wpipe[pname]) > 0:
                #self.lgr.debug('traceProcs copyOpen from %s to %s' % (parent_pid, child_pid))
                self.plist[child_pid].wpipe[pname] = list(self.plist[parent_pid].wpipe[pname])
        for sname in self.plist[parent_pid].sockets:
            if len(self.plist[parent_pid].sockets[sname]) > 0:
                #self.lgr.debug('traceProcs copyOpen from %s to %s' % (parent_pid, child_pid))
                self.plist[child_pid].sockets[sname] = list(self.plist[parent_pid].sockets[sname])
  
    def showOne(self, pid, tabs):
        pid = str(pid)
        files = ''
        sockets = ''
        pipes = ''
        if pid not in self.plist:
            print('pid %s not in plist' % pid)
            return
        for f in self.plist[pid].files:
            if len(self.plist[pid].files[f]) > 0:
                files = files + ' %s(%s)' % (f, str(self.plist[pid].files[f]))
            else:
                files = files + ' %s' % (f)

        for p in self.plist[pid].rpipe:
            if len(self.plist[pid].rpipe[p]) > 0:
                pipes = pipes + ' %s(R%s)' % (p, str(self.plist[pid].rpipe[p]))
            else:
                pipes = pipes + ' %s' % (p)
        for p in self.plist[pid].wpipe:
            if len(self.plist[pid].wpipe[p]) > 0:
                pipes = pipes + ' %s(W%s)' % (p, str(self.plist[pid].wpipe[p]))
            else:
                pipes = pipes + ' %s' % (p)
        for s in self.plist[pid].sockets:
            if len(self.plist[pid].sockets[s]) > 0:
                sockets = sockets + ' %s(S%s)' % (s, str(self.plist[pid].sockets[s]))
            else:
                sockets = sockets + ' %s' % (s)

        if self.plist[pid].args is None:
            self.trace_fh.write('%s %s  %s\n' % (tabs, pid, self.plist[pid].prog))
            print('%s %s  %s' % (tabs, pid, self.plist[pid].prog))
        else:
            self.trace_fh.write('%s %s  %s %s\n' % (tabs, pid, self.plist[pid].prog, self.plist[pid].args)) 
            print('%s %s  %s %s' % (tabs, pid, self.plist[pid].prog, self.plist[pid].args)) 

        if len(files) > 0:
            print('%s    files: %s' % (tabs, files))
            self.trace_fh.write('%s    files: %s\n' % (tabs, files))
        if len(pipes) > 0:
            print('%s    pipes: %s' % (tabs, pipes))
            self.trace_fh.write('%s    pipes: %s\n' % (tabs, pipes))
        if len(sockets) > 0:
            print('%s    sockets: %s' % (tabs, sockets))
            self.trace_fh.write('%s    sockets: %s\n' % (tabs, sockets))

    def showFamily(self, pid, tabs):
        pid = str(pid)
        self.showOne(pid, tabs)
        self.did_that.append(pid)
        tabs = tabs+'\t'
        for child in self.plist[pid].children:
            self.showFamily(child, tabs)

    def showAll(self):
        trace_path = '/tmp/procTrace.txt'
        self.trace_fh = open(trace_path, 'w') 
        self.did_that = []
        for pid in self.plist:
            ''' ignore items from initial set of processes that did not subsequently create children '''
            if pid in self.init_proc_list and len(self.plist[pid].children) == 0:
                continue
            if pid not in self.did_that:
                self.did_that.append(pid)
                tabs = ''
                self.showFamily(pid, tabs)                
        self.getNetworkAddresses()
        self.trace_fh.close()
        print('Trace report at: %s' % trace_path)
                 
    def getProg(self, pid):
        pid = str(pid)
        if pid in self.plist: 
            return self.plist[pid].prog
        else:
            return 'unknown'

    def getNetworkAddresses(self):
        for pid in self.plist:
            info = self.plist[pid].args
            if info is not None and '/bin/ip addr add' in self.plist[pid].args:
                print info.args
