class TraceFiles():
    class FileWatch():
        def __init__(self, path, outfile):
            self.path = path
            self.outfile = outfile
            self.fd = None
        
    def __init__(self, lgr):
        self.path_list = {}
        ''' only used to delete content on first use '''
        self.watched_files = []
        self.lgr = lgr
        self.open_files = {}

    def watchFile(self, path, outfile):
        self.path_list[path] = self.FileWatch(path, outfile)
        if path not in self.watched_files:
            self.lgr.debug('open and close %s' % path)
            with open(path, 'w') as fh:
                fh.write('start of RESim copy of %s\n' % path) 
            self.watched_files.append(path)

    def watchFD(self, fd, outfile):
        if fd in self.open_files:
            print('FD %d already being watched' % fd)
            return
        self.open_files[fd] = self.FileWatch(None, outfile)
        self.open_files[fd].fd = fd

    def open(self, path, fd):
        if path in self.path_list:
            self.path_list[path].fd = fd
            self.open_files[fd] = self.path_list[path]

    def close(self, fd):
        if fd in self.open_files:
            self.open_files[fd].fd = None
            del self.open_files[fd]

    def write(self, fd, the_bytes):
        if fd in self.open_files:
            with open(self.open_files[fd].outfile, 'a') as fh:
                s = ''.join(map(chr,the_bytes))
                #self.lgr.debug('writing to %s %s'  % (self.open_files[fd].outfile, s))
                fh.write(s)
            
