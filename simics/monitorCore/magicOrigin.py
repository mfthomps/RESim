import cli
from simics import *
from resimHaps import *
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
    Detect execution of magic instruction 99 and reset origin.
    Intended that a driver will execute the instruction to signify
    it is safe to reverse to that point without real world leakage.
'''
class MagicOrigin():
    def __init__(self, top, cpu, bookmarks, lgr):
        self.bookmarks = bookmarks
        self.cpu = cpu
        self.top = top
        self.lgr = lgr
        self.did_magic = False
        self.magic_hap = None
        self.break_simulation = False
        self.setMagicHap()

    def setMagicHap(self):
        if self.did_magic:
            return
        self.magic_hap = RES_hap_add_callback("Core_Magic_Instruction", self.magicHap, None)
        self.lgr.debug('magicOrigin setMagicHap')

    def deleteMagicHap(self):
        if self.magic_hap is not None:
            #self.lgr.debug('magicOrigin deleteMagicHap')
            SIM_run_alone(self.deleteMagicHapAlone, None)

    def deleteMagicHapAlone(self, dumb):
        if self.magic_hap is not None:
            RES_hap_delete_callback_id("Core_Magic_Instruction", self.magic_hap)
            self.magic_hap = None

    def setOrigin(self, dumb=None):
        #self.disconnect(run=False)
        self.top.cutRealWorld()
        #cmd = 'default_service_node0.status'
        self.top.disableReverse()
        self.top.enableReverse()
        self.did_magic = True
        self.lgr.debug('MagicOrigin to tid and then set origin')
        if self.top.isRunningTo():
            self.top.setOriginWhenStopped()
            self.lgr.debug('MagicOrigin back from calling setOriginWhen stopped, now continue')
            SIM_run_command('c')
        else:
            self.top.toTid('-1', callback=self.top.resetOrigin)
        #self.bookmarks.setOrigin(self.cpu)
        #self.lgr.debug('MagicOrigin, continue')
        #SIM_run_command('c')

    def justCutReal(self, dumb=None):
        self.top.cutRealWorld()
        self.lgr.debug('MagicOrigin justCutReal, now continue')
        SIM_run_command('c')

    def magicHap(self, dumb, cell, magic_number):
        ''' invoked when driver executes a magic instruction, indicating save to  
            establish a new origin '''
        self.lgr.debug('magicHap')
        if self.magic_hap is not None:
            self.lgr.debug('magicHap magic_hap not none, number %d' % magic_number)
            if magic_number == 99:
                if self.break_simulation:
                    SIM_break_simulation('magic stop')
                else:
                    self.lgr.debug('MagicOrigin in magic hap 99    cell: %s  number: %d' % (str(cell), magic_number))
                    if self.top.isReverseExecutionEnabled():
                        ''' reset the origin after disconnecting the service node '''
                        self.lgr.debug('MagicOrigin magicHap call to set origin')
                        self.top.stopAndGo(self.setOrigin)
                    else:
                        self.lgr.debug('MagicOrigin magicHap call to only disconnect')
                        self.top.stopAndGo(self.justCutReal)

    def didMagic(self):
        return self.did_magic

    def magicStop(self):
        self.break_simulation = True
