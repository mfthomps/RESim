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
        self.setMagicHap()

    def setMagicHap(self):
        self.magic_hap = RES_hap_add_callback("Core_Magic_Instruction", self.magicHap, None)

    def deleteMagicHap(self):
        SIM_run_alone(self.deleteMagicHapAlone, None)

    def deleteMagicHapAlone(self, dumb):
        if self.magic_hap is not None:
            RES_hap_delete_callback_id("Core_Magic_Instruction", self.magic_hap)
            self.magic_hap = None

    def setOrigin(self):
        cmd = 'disconnect-real-network'
        SIM_run_command(cmd)
        self.lgr.debug('MagicOrigin driver disconnected, set origin')
        cmd = 'disable-reverse-execution'
        SIM_run_command(cmd)
        cmd = 'enable-reverse-execution'
        SIM_run_command(cmd)
        self.bookmarks.setOrigin(self.cpu)
        self.did_magic = True
        SIM_run_command('c')

    def magicHap(self, dumb, cell, magic_number):
        ''' invoked when driver executes a magic instruction, indicating save to  
            establish a new origin '''
        if self.magic_hap is not None:
            if magic_number == 99:
                self.lgr.debug('MagicOrigin in magic hap 99    cell: %s  number: %d' % (str(cell), magic_number))
                self.top.stopAndGo(self.setOrigin)
                #SIM_run_alone(self.deleteMagicHapAlone, None)
    def didMagic(self):
        return self.did_magic
