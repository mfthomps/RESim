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
from simics import *
'''
Use a Core_Log_Message_Extended hap to capture log events for a given
object, e.g., cpu or sata controller (board.disk0.sata).
'''
class RecordLogEvents:

    def __init__(self, fname, obj_name, level, cpu, lgr):
        # setup logging
        try:
            self.f = open(fname, 'w')
        except Exception as msg:
            raise Exception("Failed to open file %s, %s" % (fname, msg))
        self.lgr = lgr
        self.obj = SIM_get_object(obj_name)
        self.level = level
        self.cpu = cpu
        self.lgr.debug('RecordLogEvents on object %s to file %s' % (obj_name, fname))
        log_cmd = '%s.log-level 4' % obj_name
        SIM_run_command(log_cmd)
        SIM_hap_add_callback_obj("Core_Log_Message_Extended", self.obj, 0, self.log_callback, None)

    def log_callback(self, not_used, obj, log_type, message, level, group):
        #type_str = conf.sim.log_types[log_type]
        if level <= self.level:
            self.f.write("%x--[%s] %s\n" % (
                    self.cpu.cycles, obj.name, message))

