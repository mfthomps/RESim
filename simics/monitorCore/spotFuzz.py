from simics import *
import cli
import os
import binascii
import random
import writeData
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
class SpotFuzz():
    def __init__(self, top, cpu, mem_utils, context_manager, backstop, fuzz_addr, break_at, lgr, reg=None, data_length=4, fail_break=[]):
        self.top = top
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.backstop = backstop
        self.fuzz_addr = fuzz_addr
        self.data_length = data_length
        self.break_at = break_at
        self.fail_break = fail_break
        self.reg = reg
        self.lgr = lgr
        self.count = 0
        self.break_hap = None
        self.breakpoint = None
        self.stop_hap = None
        self.fail_break_hap = None
        self.fail_breakpoint = []
        self.rand = []
        #if os.getenv('AFL_BACK_STOP_CYCLES') is not None:
        #    self.backstop_cycles =   int(os.getenv('AFL_BACK_STOP_CYCLES'))
        #    self.lgr.debug('afl AFL_BACK_STOP_CYCLES is %d' % self.backstop_cycles)
        #else:
        #    self.lgr.warning('no AFL_BACK_STOP_CYCLES defined, using default of 100000')
        #    self.backstop_cycles =   1000000
        self.backstop_cycles =   1000000
        self.top.debugSnap()
        here = os.getcwd()
        seed = binascii.crc32(here.encode('utf8')) 
        self.lgr.debug('spotFuzz run from %s, seed 0x%x' % (here, seed))
        random.seed(seed)
        #self.inject(dfile, snapname)
        self.top.stopDebug()
        self.disableReverse()
        self.setBreak()
        print('go')
        self.go()

    def inject(self, dfile, snapname):
        # TBD not used
        if not os.path.isfile(dfile):
            print('File not found at %s\n\n' % dfile)
            return
        with open(dfile, 'rb') as fh:
            in_data = fh.read()
            write_data = writeData.WriteData(self.top, self.cpu, in_data, 0, 
                 self.mem_utils, self.context_manager, self.backstop, snapname, self.lgr, 
                 backstop_cycles=self.backstop_cycles, set_ret_hap=False)
            write_data.write()


    def go(self, dumb=None):
        #self.lgr.debug('spotFuzz go')
        self.restore()
        self.doRand()
        self.backstop.setFutureCycle(self.backstop_cycles)
        SIM_continue(0)

    def disableReverse(self):
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')

    def restore(self):
        cli.quiet_run_command('restore-snapshot name=origin')

    def setBreak(self):
        self.breakpoint = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, self.break_at, 1, 0)
        self.break_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.breakHap, None, self.breakpoint)
        self.lgr.debug('spotFuzz set break at 0x%x context %s' % (self.break_at, str(self.cpu.current_context)))
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, None)
        #if self.fail_break is not None:
        for fail_addr in self.fail_break:
            bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, fail_addr, 1, 0)
            self.fail_breakpoint.append(bp)
        if len(self.fail_break) > 0:
            self.fail_break_hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.breakHap, None, 
                                       self.fail_breakpoint[0], self.fail_breakpoint[-1])
            self.lgr.debug('spotFuzz set fail_break at %s context %s' % (str(self.fail_break), str(self.cpu.current_context)))
   
    def breakHap(self, dumb, the_object, break_num, memory):
        if self.break_hap is None:
            return
        if self.reg is not None:
            reg_val = self.mem_utils.getRegValue(self.cpu, self.reg)
            #self.lgr.debug('spotFuzz breakHap value of %s is 0x%x from rand 0x%x count: %d' % (self.reg, reg_val, self.rand, self.count)) 
            if reg_val > 0x1000:
                print('GOT 0x%x' % regval)
        SIM_break_simulation('breakHap')

    def doRand(self):
        offset = 0
        while offset < self.data_length:
            rand = random.randrange(0, 0xffffffff)
            addr = self.fuzz_addr + offset
            self.mem_utils.writeWord(self.cpu, addr, rand) 
            self.rand.append(rand)
            offset = offset + 4

    def stopHapXXXX(self, dumb, one, exception, error_string):
        #self.lgr.debug('spotFuzz stopHap')
        if self.stop_hap is not None:
            eip = self.top.getEIP(self.cpu)
            if eip != self.break_at:
                self.lgr.debug('Stopped on eip that is not the break, assume backstop?')
                self.lgr.debug('rand was 0x%x' % self.rand)
            else:
                self.count = self.count+1
                if (self.count % 100) == 0:
                    print('count now %d' % self.count)
                if self.count > 10000:
                    print('done')
                else:
                    SIM_run_alone(self.go, None)
                self.backstop.clearCycle()

    def stopHap(self, dumb, one, exception, error_string):
        #self.lgr.debug('spotFuzz stopHap')
        if self.stop_hap is not None:
            eip = self.top.getEIP(self.cpu)
            if eip != self.break_at:
                #self.lgr.debug('Stopped on eip that is not the break, assume backstop?')
                #self.lgr.debug('rand was 0x%x' % self.rand)
                if eip not in self.fail_break:
                    print('why stop at 0x%x?' % eip)
                self.count = self.count+1
                if (self.count % 100) == 0:
                    print('count now %d' % self.count)
                    self.lgr.debug('count now %d' % self.count)
                if self.count > 1000000:
                    print('done a million')
                    self.lgr.debug('done')
                else:
                    SIM_run_alone(self.go, None)
                self.backstop.clearCycle()
            else:
                print('hit break?')
                self.lgr.debug('hit break, random values below')
                for rand in self.rand:
                    self.lgr.debug('0x%x' % rand)
                with open('/tmp/spot_fuzz_done', w) as fh:
                    fh.write('done')
                self.top.quit()


      
