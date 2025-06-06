'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
'''
Mirror reads or writes to files or file descriptors. 
Use the raw option to avoid changes to the mirrored output.
If the file descriptor is from a bind, subsequent accepts will
tracke io to the new FD (assuming sharedSyscall calls our accept)
'''
class TraceFiles():
    class FileWatch():
        def __init__(self, path, outfile):
            self.path = path
            self.outfile = outfile
            self.fd = None
        
    def __init__(self, top, traceProcs, lgr, cpu):
        self.path_list = {}
        ''' only used to delete content on first use '''
        self.watched_files = []
        self.lgr = lgr
        self.cpu = cpu
        self.top = top
        self.cell_name = top.getTopComponentName(cpu)
        self.open_files = {}
        self.traceProcs = traceProcs
        ''' for tracing of only FD, e.g., to ignore close '''
        self.tracing_fd = {}
        ''' for including file traces in watch marks '''
        self.dataWatch = None
        self.raw = False
        self.binders = {}

    def watchFile(self, path, outfile):
        self.path_list[path] = self.FileWatch(path, outfile)
        if path not in self.watched_files:
            self.lgr.debug('traceFiles open and close %s watching path %s' % (outfile, path))
            with open(outfile+'-read', 'w') as fh:
                fh.write('start of RESim copy of %s\n' % outfile) 
            with open(outfile+'-write', 'w') as fh:
                fh.write('start of RESim copy of %s\n' % outfile) 
            self.watched_files.append(path)


    def watchFD(self, fd, outfile, raw=False, web=False, all=False):
        if not all:
            tid = self.top.getTID(target=self.cell_name)
        else:
            tid = 'all'
        if tid in self.open_files and fd in self.open_files[tid]:
            print('FD %d already being watched for tid %s' % (fd, tid))
            self.lgr.debug('traceFiles watchFD FD %d already being watched tid %s' % (fd, tid))
            return
        self.web = web
        self.raw = raw
        if self.web:
            self.raw = True
        if tid not in self.open_files:
            self.open_files[tid] = {}
        self.open_files[tid][fd] = self.FileWatch(None, outfile)
        self.open_files[tid][fd].fd = fd
        if not self.raw:
            with open(outfile+'-read', 'w') as fh:
                    fh.write('start of RESim copy of FD %d\n' % fd) 
            with open(outfile+'-write', 'w') as fh:
                    fh.write('start of RESim copy of FD %d\n' % fd) 
        else:
            with open(outfile+'-read', 'wb') as fh:
                pass
            with open(outfile+'-write', 'wb') as fh:
                pass
        self.lgr.debug('traceFiles watchFD %d num open files %d' % (fd, len(self.open_files)))
        if tid not in self.tracing_fd:
            self.tracing_fd[tid] = []
        self.tracing_fd[tid].append(fd)

    def accept(self, tid, fd, new_fd):
        if tid in self.open_files and fd in self.open_files[tid]:
            if tid not in self.binders:
                self.binders[tid] = {}
            self.binders[tid][new_fd] = fd
            self.lgr.debug('traceFiles accept tid:%s new fd %d for open_files %d' % (tid, new_fd, fd))

    def open(self, path, fd):
        if path in self.path_list:
            self.path_list[path].fd = fd
            tid = self.top.getTID(target=self.cell_name)
            if tid not in self.open_files:
                self.open_files[tid] = {}
            self.open_files[tid][fd] = self.path_list[path]

    def close(self, fd):
        
        tid = self.top.getTID(target=self.cell_name)
        self.lgr.debug('traceFiles close tid:%s %d'  % (tid, fd))
        if tid in self.binders and fd in self.binders[tid]:
            del self.binders[tid][fd] 
            self.lgr.debug('traceFiles close removed binders %d for tid:%s'  % (fd, tid))
        if tid not in self.tracing_fd or fd not in self.tracing_fd[tid]:
            if tid in self.open_files and fd in self.open_files[tid] and (tid not in self.tracing_fd or fd not in self.tracing_fd[tid]):
                self.open_files[tid][fd].fd = None
                del self.open_files[tid][fd]
                self.lgr.debug('traceFiles close tid:%s FD: %d num open files %d'  % (tid, fd, len(self.open_files)))
        elif not self.raw:
            if tid in self.open_files:
                with open(self.open_files[tid][fd].outfile+'-read', 'a') as fh:
                    fh.write('\nFile closed.\n')
                with open(self.open_files[tid][fd].outfile+'-write', 'a') as fh:
                    fh.write('\nFile closed.\n')

    def nonull(self, the_bytes):
        retval = []
        index = 0
        #hx = ''.join('{:02x}'.format(x) for x in the_bytes)
        #print('the bytes is %s' % hx)
        if the_bytes is not None:
            for i in the_bytes:
                if i is not None:
                    if i >= 32 and i<128:
                        #print('got nonzero at %d' % index)
                        retval.append(i)
                else:
                    self.lgr.debug('traceFiles nonull got None in the bytes: %s' % str(the_bytes))
                index += 1
        return retval 

    def read(self, tid, fd_in, the_bytes):
        if tid in self.binders and fd_in in self.binders[tid]:
            fd = self.binders[tid][fd_in]
            self.lgr.debug('traceFiles read tid:%s fd_in: %d fd: %d len %d' % (tid, fd_in, fd, len(the_bytes)))
        else:
            fd = fd_in 
        self.lgr.debug('traceFiles read fd: 0x%x len of bytes %d' % (fd, len(the_bytes)))
        self.io(tid, fd, the_bytes, read=True, fd_in=fd_in)

    def write(self, tid, fd_in, the_bytes):
        if tid in self.binders and fd_in in self.binders[tid]:
            fd = self.binders[tid][fd_in]
        else:
            fd = fd_in 
        self.lgr.debug('traceFiles write')
        self.io(tid, fd, the_bytes, read=False, fd_in=fd_in)

    def io(self, tid, fd, the_bytes, read=False, fd_in=None):
        suf = '-write'
        if read:
            suf = '-read'
        if the_bytes is None or len(the_bytes) == 0:
            return
        if self.raw:
            if tid in self.open_files and fd in self.open_files[tid]:
                with open(self.open_files[tid][fd].outfile+suf, 'ab') as fh:
                    #cycles = b'cycle: 0x%x FD: %d --' % (self.cpu.cycles, fd_in)
                    #fh.write(cycles+bytearray(the_bytes)+b'*DONE*')
                    b_array = bytearray(the_bytes)
                    if self.web:
                            delim = b'RESIM_WEB_DELIM'
                            self.lgr.debug('traceFiles is web, tacked on the delim')
                            b_array = b_array+delim
                    fh.write(b_array)
                    self.lgr.debug('traceFiles wrote raw %d bytes' % len(b_array))
    
        else:
            stripped = self.nonull(the_bytes)
            did_write = False
            if self.traceProcs is not None and len(self.path_list) > 0:
                fname = self.traceProcs.getFileName(tid, fd)
                self.lgr.debug('traceFiles write got fname %s path in list is %s' % (fname, list(self.path_list.keys())[0]))
                if fname is not None and fname in self.path_list:
                    file_watch = self.path_list[fname]
                    with open(self.path_list[fname].outfile+suf, 'a') as fh:
                        s = ''.join(map(chr,stripped))+'\n'
                        self.lgr.debug('traceFiles got %s from traceProcs for fd %d, writing to %s %s'  % (fname, fd, self.path_list[fname].outfile, s))
                        fh.write(s)
                        fh.flush()
                        if self.dataWatch is not None:
                            self.dataWatch.markLog(s, fname)
                        did_write = True
            
            if not did_write:
                ''' tracing fd '''
                if ((tid not in self.open_files or fd not in self.open_files[tid]) and ('all' in self.open_files and fd in self.open_files['all'])):
                    tid = 'all'
                if tid in self.open_files and fd in self.open_files[tid]: 
                    with open(self.open_files[tid][fd].outfile+suf, 'a') as fh:
                        s = ''.join(map(chr,stripped))+'\n'
                        self.lgr.debug('traceFiles writing to %s %s'  % (self.open_files[tid][fd].outfile, s))
                        fh.write(s)
                        if self.dataWatch is not None:
                            prefix = 'FD:%d' % fd
                            self.dataWatch.markLog(s, prefix)
                

    def markLogs(self, dataWatch):
        self.dataWatch = dataWatch
        self.lgr.debug('traceFiles markLogs')

    def clone(self, old, new):
        self.lgr.debug('traceFiles clone old: %s new: %s' % (old, new))
        if old in self.open_files:
            self.open_files[new] = {}
            for fd in self.open_files[old]:
                self.open_files[new][fd] = self.open_files[old][fd]
        if old in self.binders:
            self.binders[new] = {}
            for fd in self.binders[old]:
                self.binders[new][fd] = self.binders[old][fd]

    def dup(self, old, new):
        self.lgr.debug('traceFiles dup old: %s new: %s' % (old, new))
        tid = self.top.getTID(target=self.cell_name)
        if tid in self.open_files and old in self.open_files[tid]:
            self.open_files[tid][new] = self.open_files[tid][old]
        if tid in self.binders and old in self.binders[tid]:
            self.binders[tid][new] = self.binders[tid][old]
        

        
