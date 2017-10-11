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
import sys
import os
import procInfo
from monitorLibs import bitArray
from monitorLibs import utils
from monitorLibs import configMgr
class codeCoverage():
    def __init__(self, cfg, lgr):
        self.lgr = lgr
        self.blocks = {}
        self.breaks = {}
        self.haps = {}
        self.missing = {}
        self.block_count = {}
        self.cfg = cfg
        self.cpu = None
        self.lgr.debug('codeCoverage init')
        self.cycle_increment = 5000000
        self.cycle_event = SIM_register_event("coverage cycle event", SIM_get_class("sim"), Sim_EC_Notsaved, self.cycle_handler, None, None, None, None)

    def cancelEvent(self):
        if self.cpu is not None:
            self.lgr.debug('codeCoverage SIM_event_cancel_time')
            SIM_event_cancel_time(self.cpu, self.cycle_event, self.cpu, None, None)

    def postEvent(self):
        SIM_event_post_cycle(self.cpu, self.cycle_event, self.cpu, self.cycle_increment, self.cycle_increment)

    def reset(self):
        self.lgr.debug('codeCoverage reset')
        for binary in self.breaks:
            for b in self.breaks[binary]:
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.haps[binary][b])
                SIM_delete_breakpoint(self.breaks[binary][b])

        self.blocks = {}
        self.breaks = {}
        self.haps = {}
        self.missing = {}
        self.block_count = {}
        self.cancelEvent()

    def getResults(self, bin_name):
        if bin_name in self.block_count:
            return self.block_count[bin_name], len(self.breaks[bin_name])
        else:
            self.lgr.error('no block counts for %s' % bin_name)
            return None, None

    def getUntouched(self, bin_name):
        if bin_name in self.block_count:
            retval = []
            for key in self.breaks[bin_name].keys():
                retval.append(key)
            return retval
        else:
            self.lgr.error('no basic block for %s' % bin_name)
            return None

    def getBitArrayTouched(self, bin_name):
        if bin_name in self.blocks:
            barray = 0
            i = 0
            for block in self.blocks[bin_name]:
                if block not in self.breaks[bin_name].keys():
                    barray = bitArray.setbit(barray, i)
                i += 1
            return bitArray.dump(barray)        
        else:
            self.lgr.error('no basic block for %s' % bin_name)
        return None

    def setBreaks(self, binary, cpu, pid):
        num_blocks = 0
        self.blocks[binary] = []
        self.missing[binary] = []
        self.breaks[binary] = {}
        self.haps[binary] = {}
        self.cpu = cpu
        cb = utils.getCommonName(binary)
        dest = os.path.join(self.cfg.artifact_dir, utils.pathFromCommon(cb), 'ida')
        fname = os.path.join(dest, binary, "blocks.txt")
        with open(fname) as fhandle:
            lines = fhandle.readlines()
            for function in lines:
                items = function.split()
                for b in items[2:]:
                    b_hex = int(b, 16)
                    self.blocks[binary].append(b_hex)
                    num_blocks += 1
        self.lgr.debug('codeCoverage setBreaks num blocks for %s is %d' % (binary, num_blocks))
        self.block_count[binary] = num_blocks
        pinfo = procInfo.procInfo(binary, cpu, pid)
        for b in self.blocks[binary]:
            block = b
            phys_block = cpu.iface.processor_info.logical_to_physical(block, Sim_Access_Read)
            if phys_block.address != 0:
                #self.lgr.debug('codeCoverage setBreaks adding break for %s %x to phys: %x' % (binary, block, phys_block.address))
                self.breaks[binary][block] = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, 
                      phys_block.address, 1, 0)
                self.haps[binary][block] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.coverageCallback, pinfo, 
                      self.breaks[binary][block])
            else:
                #self.lgr.debug('codeCoverage setBreaks add to missing 0x%x for %s' % (block, binary))
                self.missing[binary].append(block)

    def updateBreaks(self, binary, cpu, pid):
        if binary not in self.missing:
            self.lgr.debug('codeCoverage, updateBreaks %s not yet in dictionary, must be about to exec return?' % binary)
            return
        blocks = list(self.missing[binary])
        self.lgr.debug('codeCoverge updateBreaks, %d remain to be mapped' % len(self.missing[binary]))
        pinfo = procInfo.procInfo(binary, cpu, pid)
        for b in blocks:
            phys_block = cpu.iface.processor_info.logical_to_physical(b, Sim_Access_Read)
            if phys_block.address != 0:
                self.lgr.debug('codeCoverage updateBreaks for %x' % b)
                self.breaks[binary][b] = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, 
                      phys_block.address, 1, 0)
                self.haps[binary][b] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.coverageCallback, pinfo, 
                      self.breaks[binary][b])
                self.missing[binary].remove(b)
                               
  
    def coverageCallback(self, pinfo, third, forth, fifth):
        reg_num = pinfo.cpu.iface.int_register.get_number("eip")
        eip = pinfo.cpu.iface.int_register.read(reg_num)
        self.lgr.debug('codeCoverage, coverageCallback at eip 0x%x' % eip)

        self.cancelEvent()
        
        if pinfo.comm in self.breaks and eip in self.breaks[pinfo.comm]:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.haps[pinfo.comm][eip])
            SIM_delete_breakpoint(self.breaks[pinfo.comm][eip])
            del self.haps[pinfo.comm][eip]
            del self.breaks[pinfo.comm][eip]
            self.postEvent()
        else:
            self.lgr.error('codeCoverage, coverageCallback at eip 0x%x, but not found in breaks' % eip)
        
    def cycle_handler(self, obj, cycles):
        ''' avoid packageMgr timeouts for code loops '''
        cycle = SIM_cycle_count(self.cpu)
        self.lgr.debug('cycle_handler (keep alive) %x cycles  ' % (cycle))
        self.postEvent()
