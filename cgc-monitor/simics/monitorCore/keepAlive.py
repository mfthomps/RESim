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
import time
from monitorLibs import utils
from monitorLibs import configMgr
class keepAlive():
    '''
    Write a log entry every n cycles to let the putMonitor know this monitor is still alive
    '''
    def __init__(self, top, cfg, lgr):
        self.lgr = lgr
        self.cfg = cfg
        self.cpu = None
        self.top = top
        self.lasttime = None
        self.kill_count = 0
        #self.cycle_increment = 25000000
        self.cycle_increment = int(cfg.keep_alive_cycles)
        self.kill_after_count = int(cfg.keep_alive_kill_count)
        self.lgr.debug('keepAlive init, cycle increment is %d' % self.cycle_increment)
        self.cycle_event = SIM_register_event("keepAlive cycle event", SIM_get_class("sim"), Sim_EC_Notsaved, self.cycle_handler, None, None, None, None)
        self.rtc_start = None

    def resetKillCount(self):
        self.kill_count = 0

    def cancelEvent(self):
        if self.cpu is not None:
            cycle = self.cpu.cycles
            self.lgr.debug('keepAlive cancel event at 0x%x' % cycle)
            SIM_event_cancel_time(self.cpu, self.cycle_event, self.cpu, None, None)
            self.lasttime = None
            self.kill_count = 0
            self.rtc_start = None

    def postEvent(self, cpu):
        self.cpu = cpu
        cycle = self.cpu.cycles
        #self.lgr.debug('keepAlive postEvent at %x cycles  ' % (cycle))
        SIM_event_post_cycle(cpu, self.cycle_event, cpu, self.cycle_increment, self.cycle_increment)
        if self.lasttime is None:
            self.lasttime = time.time()
        if self.rtc_start == None:
            self.rtc_start = self.top.getWallSeconds(self.cpu)

    def cycle_handler(self, obj, cycles):
        ''' avoid packageMgr timeouts for things like rop on big xml validation'''
        cycle = self.cpu.cycles
        self.postEvent(self.cpu)
        now = time.time()
        if self.lasttime is not None:
            delta = now - self.lasttime
            if delta > 30:
                rtc_seconds = self.top.getWallSeconds(self.cpu) - self.rtc_start
                self.lgr.debug('keepAlive cycle_handler at 0x%x cycles %d rtc seconds ' % (cycle, rtc_seconds))
                self.lasttime = now
                self.kill_count += 1
                 
                if self.kill_after_count != 0 and self.kill_count > self.kill_after_count:
                    self.lgr.debug('keepAlive, kill count %d exceeded, force quit the replay' % self.kill_after_count)
                    self.top.forceQuitReplay()

        else:
            self.lasttime = now
            
