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

    def watchFile(self, path, outfile):
        self.path_list[path] = self.FileWatch(path, outfile)
        if path not in self.watched_files:
            self.lgr.debug('open and close %s' % outfile)
            with open(outfile, 'w') as fh:
                fh.write('start of RESim copy of %s\n' % outfile) 
            self.watched_files.append(path)

    def watchFD(self, fd, outfile):
        if fd in self.open_files:
            print('FD %d already being watched' % fd)
            return
        self.open_files[fd] = self.FileWatch(None, outfile)
        self.open_files[fd].fd = fd
        self.lgr.debug('TraceFiles watchFD %d num open files %d' % (fd, len(self.open_files)))
        

    def open(self, path, fd):
        if path in self.path_list:
            self.path_list[path].fd = fd
            self.open_files[fd] = self.path_list[path]

    def close(self, fd):
        if fd in self.open_files:
            self.open_files[fd].fd = None
            del self.open_files[fd]
            self.lgr.debug('TraceFiles close %d num open files %d'  % (fd, len(self.open_files)))

    def write(self, pid, fd, the_bytes):
        if self.traceProcs is not None:
            fname = self.traceProcs.getFileName(pid, fd)
            self.lgr.debug('TraceFiles write got fname %s' % fname)
            if fname is not None and fname in self.path_list:
                file_watch = self.path_list[fname]
                with open(self.path_list[fname].outfile, 'a') as fh:
                    s = ''.join(map(chr,the_bytes))
                    self.lgr.debug('TraceFiles got %s from traceProcs for fd %d, writing to %s %s'  % (fname, fd, self.path_list[fname].outfile, s))
                    fh.write(s)
                    fh.flush()
        
                 
        elif fd in self.open_files:
            with open(self.open_files[fd].outfile, 'a') as fh:
                s = ''.join(map(chr,the_bytes))
                self.lgr.debug('TraceFiles writing to %s %s'  % (self.open_files[fd].outfile, s))
                fh.write(s)
            
