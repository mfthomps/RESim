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
        
    def __init__(self, traceProcs, lgr):
        self.path_list = {}
        ''' only used to delete content on first use '''
        self.watched_files = []
        self.lgr = lgr
        self.open_files = {}
        self.traceProcs = traceProcs
        ''' for tracing of only FD, e.g., to ignore close '''
        self.tracing_fd = []
        ''' for including file traces in watch marks '''
        self.dataWatch = None
        self.raw = False
        self.binders = {}

    def watchFile(self, path, outfile):
        self.path_list[path] = self.FileWatch(path, outfile)
        if path not in self.watched_files:
            self.lgr.debug('traceFiles open and close %s' % outfile)
            with open(outfile+'-read', 'w') as fh:
                fh.write('start of RESim copy of %s\n' % outfile) 
            with open(outfile+'-write', 'w') as fh:
                fh.write('start of RESim copy of %s\n' % outfile) 
            self.watched_files.append(path)


    def watchFD(self, fd, outfile, raw=False):
        if fd in self.open_files:
            print('FD %d already being watched' % fd)
            self.lgr.debug('traceFiles watchFD FD %d already being watched' % fd)
            return
        self.raw = raw
        self.open_files[fd] = self.FileWatch(None, outfile)
        self.open_files[fd].fd = fd
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
        self.lgr.debug('TraceFiles watchFD %d num open files %d' % (fd, len(self.open_files)))
        self.tracing_fd.append(fd)

    def accept(self, tid, fd, new_fd):
        if fd in self.open_files:
            self.binders[new_fd] = fd
            self.lgr.debug('TraceFiles accept new fd %d for open_files %d' % (new_fd, fd))

    def open(self, path, fd):
        if path in self.path_list:
            self.path_list[path].fd = fd
            self.open_files[fd] = self.path_list[path]

    def close(self, fd):
        if fd not in self.tracing_fd:
            if fd in self.open_files and fd not in self.tracing_fd:
                self.open_files[fd].fd = None
                del self.open_files[fd]
                self.lgr.debug('TraceFiles close %d num open files %d'  % (fd, len(self.open_files)))
        elif not self.raw:
            with open(self.open_files[fd].outfile+'-read', 'a') as fh:
                fh.write('\nFile closed.\n')
            with open(self.open_files[fd].outfile+'-write', 'a') as fh:
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
                    self.lgr.debug('TraceFiles nonull got None in the bytes: %s' % str(the_bytes))
                index += 1
        return retval 

    def read(self, tid, fd_in, the_bytes):
        if fd_in in self.binders:
            fd = self.binders[fd_in]
        else:
            fd = fd_in 
        self.lgr.debug('traceFiles read')
        self.io(tid, fd, the_bytes, read=True)

    def write(self, tid, fd_in, the_bytes):
        if fd_in in self.binders:
            fd = self.binders[fd_in]
        else:
            fd = fd_in 
        self.lgr.debug('traceFiles write')
        self.io(tid, fd, the_bytes, read=False)

    def io(self, tid, fd, the_bytes, read=False):
        suf = '-write'
        if read:
            suf = '-read'
        if the_bytes is None:
            return
        if self.raw:
            if fd in self.open_files:
                with open(self.open_files[fd].outfile+suf, 'ab') as fh:
                    fh.write(bytearray(the_bytes))
                    self.lgr.debug('traceFiles wrote raw %d bytes' % len(the_bytes))
    
        else:
            stripped = self.nonull(the_bytes)
            did_write = False
            if self.traceProcs is not None and len(self.path_list) > 0:
                fname = self.traceProcs.getFileName(tid, fd)
                self.lgr.debug('TraceFiles write got fname %s' % fname)
                if fname is not None and fname in self.path_list:
                    file_watch = self.path_list[fname]
                    with open(self.path_list[fname].outfile+suf, 'a') as fh:
                        s = ''.join(map(chr,stripped))+'\n'
                        self.lgr.debug('TraceFiles got %s from traceProcs for fd %d, writing to %s %s'  % (fname, fd, self.path_list[fname].outfile, s))
                        fh.write(s)
                        fh.flush()
                        if self.dataWatch is not None:
                            self.dataWatch.markLog(s, fname)
                        did_write = True
            
            if not did_write and fd in self.open_files:
                ''' tracing fd '''
                with open(self.open_files[fd].outfile+suf, 'a') as fh:
                    s = ''.join(map(chr,stripped))+'\n'
                    self.lgr.debug('TraceFiles writing to %s %s'  % (self.open_files[fd].outfile, s))
                    fh.write(s)
                    if self.dataWatch is not None:
                        prefix = 'FD:%d' % fd
                        self.dataWatch.markLog(s, prefix)
                

    def markLogs(self, dataWatch):
        self.dataWatch = dataWatch
        self.lgr.debug('TraceFiles markLogs')
