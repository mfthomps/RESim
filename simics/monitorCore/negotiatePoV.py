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
import struct
import binascii
from monitorLibs import forensicEvents
'''
Track PoV negotiations and determine if PoVs were successful.
'''
class negotiatePoV():
    def __init__(self, top, cfg, master_cfg, target_log, lgr):
        self.comm = {}
        self.pid = {}
        self.clearAllValues()
        self.lgr = lgr
        self.top = top
        self.cfg = cfg
        self.target_log = target_log
        self.master_cfg = master_cfg
        self.pov_regs = []
        self.pov_regs.append('eax')
        self.pov_regs.append('ecx')
        self.pov_regs.append('edx')
        self.pov_regs.append('ebx')
        self.pov_regs.append('esp')
        self.pov_regs.append('ebp')
        self.pov_regs.append('esi')
        self.pov_regs.append('edi')

    def clearValues(self, seed):
      try:
        self.pov_type.pop(seed)
        self.pov_ipmask.pop(seed)
        self.pov_regmask.pop(seed)
        self.pov_regnum.pop(seed)
        self.type1_eip.pop(seed)
        self.type1_regvalue.pop(seed)
        self.type2_addr.pop(seed)
        self.type2_size.pop(seed)
        self.type2_length.pop(seed)
        self.type2_proof.pop(seed)
        self.partial_read.pop(seed)
        self.partial_write.pop(seed)
        self.page.pop(seed)
        self.cpu.pop(seed)
        self.cell_name.pop(seed)
      except:
        pass

    def clearAllValues(self):
        self.pov_type = {}
        self.pov_ipmask = {}
        self.pov_regmask = {}
        self.pov_regnum = {}
        self.type1_eip = {}
        self.type1_regvalue = {}
        self.type2_addr = {}
        self.type2_size = {}
        self.type2_length = {}
        self.type2_proof = {}
        self.partial_read = {}
        self.partial_write = {}
        self.page = {}
        self.cpu = {}
        self.cell_name = {}
        
    def newPoV(self, comm, pid, cpu, cell_name, master_cfg):
        '''
        Invoke whenever the monitor starts processing a new pov
        '''
        seed = self.target_log.findSeed(pid, cell_name)
        self.lgr.debug('negotiate newPov for seed %s' % (seed))
        self.comm[seed] = comm
        self.pid[seed] = pid
        self.cpu[seed] = cpu
        self.cell_name[seed] = cell_name
        self.master_cfg = master_cfg

    def getValue(self, s):
        '''
        32 bit little endian string to an integer
        '''
        retval = None
        try: 
            v = binascii.unhexlify(s)
        except:
            self.lgr.error('negotiatePov, getValue, could not unhexlfiy %s' % s)
            exit
        try:
            retval = struct.unpack("<I", v)[0]
        except:
            self.lgr.error('negotiatePov, getValue, could not get int from %s v is %s' % (s, v))
            exit
        return retval

    def handlePartialWrite(self, buf, seed):
        retval = None
        if (len(buf) % 2) == 1:
            buf = '0'+buf
        if seed not in self.partial_write:
            self.partial_write[seed] = buf
        else:
            self.partial_write[seed] = self.partial_write[seed]+buf
        if len(self.partial_write[seed]) == 8:
            retval = self.partial_write[seed]
            self.partial_write.pop(seed)
        elif len(self.partial_write[seed]) > 8:
            retval = self.partial_write[seed][:8]
            self.partial_write[seed] = self.partial_write[seed][8:]
        else:
            self.lgr.debug('handlePartialWrite, not enough data in partial %s, return' % self.partial_write[seed])
        return retval
            
    def handlePartialRead(self, buf, seed):
        '''
        append the given buf (if any) to a running buffer.
        if there are four bytes of data (8 characters) in the buffer,
        return those and adjust the buffer
        '''
        retval = None
        if seed not in self.partial_read:
            self.partial_read[seed] = buf
        else:
            self.partial_read[seed] = self.partial_read[seed]+buf
        if len(self.partial_read[seed]) == 8:
            retval = self.partial_read[seed]
            self.partial_read.pop(seed)
        elif len(self.partial_read[seed]) > 8:
            retval = self.partial_read[seed][:8]
            self.partial_read[seed] = self.partial_read[seed][8:]
        else:
            self.lgr.debug('handlePartialRead, not enough data in partial %s, return' % self.partial_read[seed])
        return retval

    def isType2(self, seed):
        if seed in self.pov_type and self.pov_type[seed] == 2:
            return True
        else:
            return False
        
    def recordNegotiate(self, call_num, in_buf, pid, cell_name):
        '''
        Called each time monitor detects a read or write on fd 3 by a PoV.
        call_num is read or write.  buf is the hex string values given by the PoV.
        Uses recursion to handle multiple 32 bit values in one buf
        If a type 2 negotiation succeeds, return the bookmark of the first read
        '''
      
        seed = self.target_log.findSeed(pid, cell_name)
        retval = None
        buf = None
        if call_num == self.top.SYS_WRITE:
            buf = self.handlePartialWrite(in_buf, seed)
        else:
            buf = self.handlePartialRead(in_buf, seed)
        if buf is None:
            return
                
        if seed not in self.pov_type:
            if call_num == self.top.SYS_WRITE:
                self.pov_type[seed] = self.getValue(buf[:8])
                self.lgr.debug("recordNegotiate got pov type of %d" % self.pov_type[seed])
                if seed in self.partial_write and len(self.partial_write[seed]) >= 8:
                    self.recordNegotiate(call_num, '', pid, cell_name) 
            else:
                self.lgr.error('negotiate, recordNegotiate, expected transmit, got %d' % call_num)
        else:
            if self.pov_type[seed] == 1:
                self.lgr.debug('negotiate, is type I call_num %d' % call_num)
                if call_num == self.top.SYS_WRITE:
                    if seed not in self.pov_ipmask:
                        self.pov_ipmask[seed] = self.getValue(buf[:8]) 
                        self.lgr.debug("got pov_ipmask  of %x" % self.pov_ipmask[seed])
                        if seed in self.partial_write and len(self.partial_write[seed]) >= 8:
                            self.recordNegotiate(call_num, '', pid, cell_name)
                    elif seed not in self.pov_regmask:
                        self.pov_regmask[seed] = self.getValue(buf[:8]) 
                        self.lgr.debug("got pov_regmask  of %x" % self.pov_regmask[seed])
                        if seed in self.partial_write and len(self.partial_write[seed]) >= 8:
                            self.recordNegotiate(call_num, '', pid, cell_name)
                    elif seed not in self.pov_regnum:
                        self.pov_regnum[seed] = self.getValue(buf[:8]) 
                        self.lgr.debug("got pov_regnum  of %d" % self.pov_regnum[seed])
                        if seed in self.partial_write and len(self.partial_write[seed]) > 0:
                            self.lgr.error("unexpected extra data sent during type 1 negotiation %s" % self.partial_write[seed])
                else:
                    # is a SYS_READ
                    if seed not in self.pov_ipmask:
                        self.lgr.error('negotiate, recordNegotiate, no ipmask, expected transmit, got %d' % call_num)
                    else:
                        if seed not in self.type1_eip:
                            self.type1_eip[seed] = self.getValue(buf[:8]) 
                            self.lgr.debug("got type1_eip  of 0x%x, buf was %s" % (self.type1_eip[seed], buf))
                            if seed in self.partial_read and len(self.partial_read[seed]) >= 8:
                                self.recordNegotiate(call_num, '', pid, cell_name)
                        elif seed not in self.type1_regvalue:
                            self.type1_regvalue[seed] = self.getValue(buf[:8]) 
                            self.lgr.debug("got type1_regvalue  of 0x%x" % self.type1_regvalue[seed])
                            if seed in self.partial_read and len(self.partial_read[seed]) >= 0:
                                self.lgr.error("unexpected extra data read during type 1 negotiation %s" % buf)
            else:
                # a type II PoV
                self.lgr.debug('negotiate, is type II call_num %d seed %s' % (call_num, seed))
                if call_num == self.top.SYS_WRITE:
                    self.type2_proof[seed] = buf
                    self.lgr.debug('negotiate type 2 PoV proof is: %s  seed: %s' % (buf, seed))
                    if seed not in self.page:
                        self.lgr.debug('negotiate type 2 PoV but page never read')
                        self.getPage(self.cpu[seed], pid, cell_name)
                        if buf in self.page[seed]:
                            self.lgr.debug('but value is correct!')
                        else:
                            self.lgr.debug('value is not correct')
                    elif buf in self.page[seed]:
                        offset = self.page[seed].find(buf) 
                        address = offset/2 + self.cfg.protected_start
                        if (offset < (len(self.page[seed])-4)) and buf in self.page[seed][offset+4:]:
                            self.lgr.critical('negotiate type 2 pov found two copies of %s in %s' % (buf, self.page[seed]))
                        # the given value is somewhere in the page.
                        self.lgr.debug('negotiate type 2 PoV success at address 0x%x!' % address)
                        entry = 'Type 2 POV, value: %s' % buf
                        self.top.addLogEvent(self.cell_name[seed], self.pid[seed], self.comm[seed], forensicEvents.POV_2, entry)
                        if self.master_cfg.stop_on_memory:
                           retval = address
                    else: 
                        self.lgr.debug('negotiate type 2 PoV fail len of page is %d' % len(self.page[seed]))
                        self.lgr.debug(self.page)
                else:
                    # is a read, TBD use values for protected memory locations vice config file
                    self.lgr.debug('negotiate type 2 receive, buf is %s' % buf)
        return retval
           
    def getPage(self, cpu, pid, cell_name):   
        '''
        Assumes CB is active process on the given cpu
        '''
        seed = self.target_log.findSeed(pid, cell_name)
        if seed not in self.page:
            self.page[seed] = self.top.getBytes(cpu, self.cfg.protected_length, self.cfg.protected_start)

    def returnPage(self, pid, cell_name):
        seed = self.target_log.findSeed(pid, cell_name)
        return self.page[seed]

    def checkType1(self, frame, pid, cell_name): 
        '''
        Determine if a type I PoV succeeded based on the negotiated eip/register and the given frame.
        '''
        seed = self.target_log.findSeed(pid, cell_name)
        entry = None
        if seed not in self.type1_eip or seed not in self.pov_regnum or seed not in self.type1_regvalue:
            self.lgr.debug('checkType1 called but no complete type 1 negotiation for seed %s' % seed)
            return entry
        reg_name = self.pov_regs[self.pov_regnum[seed]]
        masked_eip = frame['eip'] & self.pov_ipmask[seed]
        masked_reg = frame[reg_name] & self.pov_regmask[seed]
        self.lgr.debug('negotiatePoV check_type1, negotiated eip is %x, actual was %x' % (self.type1_eip[seed], masked_eip))
        self.lgr.debug('negotiatePoV check_type1, negotiated reg is %s, value %x, actual was %x' % (reg_name, 
            self.type1_regvalue[seed], masked_reg))
        # And value from frame with stored mask & then compare with the negotiated value
        if self.type1_eip[seed] == masked_eip and self.type1_regvalue[seed] == masked_reg:
            entry = 'Type 1 POV eip:0x%x %s:0x%x' % (frame['eip'], reg_name, frame[reg_name]) 
            self.top.addLogEvent(self.cell_name[seed], self.pid[seed], self.comm[seed], forensicEvents.POV_1, entry)
            self.lgr.debug('negotiatePoV type 1 success!')
        else:
            self.lgr.debug('negotiatePoV type 1 failure')
        return entry
