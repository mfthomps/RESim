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

class debugInfo():
    def __init__(self, context_manager, hap_manager, pid, comm, command, event_type, sig_eip, 
                    cb_version, pov_version, cell_name, cpu, frame, event_value, lgr, negotiate_result=None, unmapped_eip=False, auto_analysis=False):
        self.context_manager = context_manager
        self.hap_manager = hap_manager
        self.pid = pid
        self.comm = comm
        self.command = command
        self.event_type = event_type
        self.event_value = event_value
        self.sig_eip = sig_eip
        self.cb_version = cb_version
        self.pov_version = pov_version
        self.del_breakpoint = None
        self.cycle = None
        self.cell_name = cell_name
        self.cpu = cpu
        self.frame = frame
        self.lgr = lgr
        self.negotiate_result = negotiate_result
        self.unmapped_eip = unmapped_eip
        self.auto_analysis = auto_analysis

