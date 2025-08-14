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
import os
from simics import *
import cli
import time
import resimSimicsUtils
class SkipToMgr():
    def __init__(self, reverse_mgr, cpu, lgr):
        self.reverse_mgr = reverse_mgr
        self.cpu = cpu
        self.lgr = lgr
        self.SIMICS_VER = resimSimicsUtils.version()
    
    def reverseEnabled(self):
        if not self.reverse_mgr.nativeReverse():
            return self.reverse_mgr.reverseEnabled()
        else:
            cmd = 'sim.status'
            #cmd = 'sim.info.status'
            dumb, ret = cli.quiet_run_command(cmd)
            rev = ret.find('Reverse Execution')
            after = ret[rev:]
            parts = after.split(':', 1)
            if parts[1].strip().startswith('Enabled'):
                return True
            else:
                return False
    
    def skipToTest(self, cycle, disable_vmp=False):
        if not self.reverse_mgr.nativeReverse():
            retval = self.reverse_mgr.skipToCycle(cycle)
            now = self.cpu.cycles
            if now != cycle:
                self.lgr.error('skipToMgr skipToTest reverseMgr failed.  wanted 0x%x go 0x%x' % (cycle, now))
        else:
            limit=100
            count = 0
            while SIM_simics_is_running() and count<limit:
                self.lgr.error('skipToTest but simics running')
                time.sleep(1)
                count = count+1
                    
            if count >= limit:
                return False
            if not self.reverseEnabled():
                self.lgr.error('Reverse execution is disabled.')
                return False
            already_disabled = False
            retval = True
            if disable_vmp:
                cli.quiet_run_command('pselect %s' % self.cpu.name)
                result=cli.quiet_run_command('disable-vmp')
                self.lgr.debug('skipToTest disable-vmp result %s' % str(result))
                already_disabled = False
                if 'VMP already disabled' in result[1]:
                    already_disabled = True
            
            cmd = 'skip-to cycle = %d ' % cycle
            cli.quiet_run_command(cmd)
            
            now = self.cpu.cycles
            if now != cycle:
                self.lgr.error('skipToTest failed wanted 0x%x got 0x%x' % (cycle, now))
                time.sleep(1)
                cli.quiet_run_command(cmd)
                now = self.cpu.cycles
                if now != cycle:
                    self.lgr.error('skipToTest failed again wanted 0x%x got 0x%x' % (cycle, now))
                    retval = False
    
            if disable_vmp:
                if not already_disabled:
                    try:
                        cli.quiet_run_command('enable-vmp')
                    #except cli_impl.CliError:
                    except:
                        pass
    
        return retval
    
