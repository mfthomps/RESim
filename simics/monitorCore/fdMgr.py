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
    Manage Dmod FD allocation
'''
FD_MAX = 255
FD_MIN = 230
class FDMgr():
    def __init__(self, lgr):
        self.lgr = lgr
        self.fd_map = {}
        self.dmod_map = {}

    def getFD(self, tid, dmod_path):
        retval = None
        if tid not in self.fd_map:
            self.fd_map[tid] = []
        fd_try = FD_MAX
        while fd_try > FD_MIN:
            if fd_try not in self.fd_map[tid]:
               retval = fd_try
               self.fd_map[tid].append(fd_try)
               break
            fd_try = fd_try - 1
        if retval is None:
            self.lgr.error('fdMgr getFD failed to find FD above %d' % FD_MIN)
        else:
            key = '%s:%d' % (tid, retval)
            self.dmod_map[key] = dmod_path
        return retval

    def close(self, tid, fd, dmod_path):
        if tid in self.fd_map:
            if fd in self.fd_map[tid]:
                self.fd_map[tid].remove(fd)
                key = '%s:%d' % (tid, fd)
                if self.dmod_map[key] == dmod_path:
                    del self.dmod_map[key]
                else:
                    self.lgr.error('fdMgr close path %s does not match dmod map' % dmod_path)
            else:
                self.lgr.error('fdMgr close fd %d not in map for tid %s' % (fd, tid))
        else:
            self.lgr.error('fdMgr close tid %s not in fd map' % (tid))

    def hasFDOpen(self, tid, fd, dmod_path):
        retval = False  
        if tid in self.fd_map and fd in self.fd_map[tid]:
            key = '%s:%d' % (tid, fd)
            if self.dmod_map[key] == dmod_path:
                retval = True
        return retval


