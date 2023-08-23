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
import decodeArm
import decode
import resimUtils
'''
Track kernel buffers used with read/recv calls

Kernel buffer size is determined by looking for a fixed character (Z) following a backtrack
of the first write to the application read buffer.
'''
class Kbuffer():
    def __init__(self, top, cpu, context_manager, mem_utils, data_watch, lgr, commence=None):
        self.context_manager = context_manager
        self.mem_utils = mem_utils
        self.data_watch = data_watch
        self.top = top
        self.cpu = cpu
        self.lgr = lgr
        self.watching_addr = None
        self.kbufs = []
        self.kbuf_len = None
        self.write_hap = None
        self.read_count = None
        self.buf_remain = None
        self.user_addr = None
        self.user_count = None
        self.orig_buffer = None
        self.kernel_cycle_of_write = None
        self.hack_count = 0

    def read(self, addr, count):
        ''' syscall got a read call. '''
        self.lgr.debug('Kbuffer read addr 0x%x' % addr)
        if self.watching_addr is None:
            self.watching_addr = addr
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, addr, 1, 0)
            self.write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, None, proc_break, 'kbuffer_write')
            self.read_count = count
            self.lgr.debug('Kbuffer read set write_hap count 0x%x' % count)

            self.user_addr = addr
            self.user_count = count
            self.orig_buffer = self.mem_utils.readBytes(self.cpu, addr, count)
        if self.buf_remain is not None:
            self.lgr.debug('Kbuffer read buf_remain is %d count %d' % (self.buf_remain, count))
            if self.buf_remain < count:
                new_addr = addr + self.buf_remain
                self.watching_addr = new_addr
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, new_addr, 1, 0)
                self.write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, None, proc_break, 'kbuffer_write')
                self.read_count = count
                self.lgr.debug('Kbuffer read, set new hap at new_addr 0x%x read_count %d' % (new_addr, count))
                self.data_watch.registerHapForRemoval(self)

    def gotBufferCallback(self, buf_addrs):
        ''' Not yet used, would need to stop simulation'''
        if len(buf_addrs) == 0:
            self.lgr.error('Kbuffer gotBufferCallback called with no buffers')
        else:
            src = buf_addrs[0]
            self.lgr.debug('Kbuffer gotBufferCallback, src 0x%x' % src)
            self.updateBuffers(src)

    def findArmBuf(self):
        eip = self.top.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('Kbuffer findArmBuf, is ARM, expect a str: %s' % instruct[1])
        if instruct[1].startswith('str'):
            op2, op1 = decodeArm.getOperands(instruct[1])
            self.lgr.debug('Kbuffer findArmBuf op1 is %s' % op1)
            our_reg = op1
            #self.top.revRegSrc(op1, kernel=True, callback=self.gotBufferCallback, taint=False)
            ''' Simulation is running.  So make hacky assumption about there being a recent ldm instruction to avoid stopping '''
            limit = 20
            gotone = False
            skipped_list = []
            for i in range(limit):
                eip = eip - self.mem_utils.WORD_SIZE
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('findArmBuf instruct: %s' % instruct[1])
                if instruct[1].startswith('ldm') or instruct[1].startswith('ldr'):
                    op2, op1 = decodeArm.getOperands(instruct[1])
                    writeback = False
                    if instruct[1].startswith('ldm'):
                        if op1.endswith('!'):
                            op1 = op1[:-1]
                            writeback = True
                        self.lgr.debug('findArmBuf op1 is %s from  %s' % (op1, instruct[1]))
                        value = self.top.getReg(op1, self.cpu)
                        if writeback:
                            num_regs = op2.count(',')+1
                            value = value - self.mem_utils.WORD_SIZE * num_regs
                    else:
                        ''' assume ldr '''
                        if op1 == our_reg:
                            value = decodeArm.getAddressFromOperand(self.cpu, op2, self.lgr, after=True)
                            our_op2 = op2
                            ''' adjust based on quantity of ldr instructions that adjusted the register value '''
                            for skipped in skipped_list:
                                op2, op1 = decodeArm.getOperands(skipped)
                                if op2 == our_op2: 
                                    self.lgr.debug('findArmBuf would adjust per %s' % op2)
                                    if ',' in op2:
                                        adjust = decodeArm.getValue(op2.split(',')[1], self.cpu)
                                        value = value - adjust
                                
                        else:
                            self.lgr.debug('findARmBuf not our reg, skip it, but record so we can adjust register per arm side-effects')
                            skipped_list.append(instruct[1])
                            continue
                    self.lgr.debug('findArmBuf buf found at 0x%x' % value)
                    if self.kernel_cycle_of_write is None:
                        self.kernel_cycle_of_write = self.cpu.cycles - 1
                    self.updateBuffers(value)
                    gotone = True
                    break
            if not gotone:
                self.lgr.error('findArmBuf failed to find instruction sequence')
        else:
            self.lgr.error('findArmBuf, expected str instruction, got %s' % instruct[1])
            

                    

    def updateBuffers(self, src):
        if self.kbuf_len is not None and src > self.kbufs[-1] and src < (self.kbufs[-1]+self.kbuf_len):
            ''' The read is from the same kernel buffer used on the previous read.'''
            self.lgr.debug('Kbuffer updateBuffers read from previous kernel buffer 0x%x' % self.kbufs[-1])
            kbuf_remaining = (self.kbufs[-1] + self.kbuf_len) - src + 1
            if self.read_count > kbuf_remaining:
                ''' change break to write of first byte from next buffer '''
                new_break = self.watching_addr + kbuf_remaining
                self.lgr.debug('Kbuffer, count given in read syscall %d greater than end of remaining kbuf %d, set next break at 0x%x' % (self.read_count, 
                            kbuf_remaining, new_break))
                SIM_run_alone(self.replaceHap, new_break)
                self.watching_addr = new_break

        else:  
            self.lgr.debug('Kbuffer updateBuffers adding kbuf of 0x%x, kbuf_len is %s' % (src, str(self.kbuf_len)))
            self.kbufs.append(src)
            print('adding kbuf 0x%x' % src)
            if self.kbuf_len is None or (self.buf_remain is None or self.buf_remain > 100):
                max_bad = 1000
                special = ord('Z')
                done = False 
                cur_addr = src
                bad_count = 0
                last_good = None
                while not done:
                    b = self.mem_utils.readByte(self.cpu, cur_addr)
                    #self.lgr.debug('b is %d' % b)
                    if b != special:
                        bad_count += 1
                        if bad_count > max_bad:
                            done = True
                            break
                    else:
                        last_good = cur_addr
                        bad_count = 0
                    cur_addr += 1
                if last_good is None:
                    if self.kbuf_len is None:
                        self.lgr.error('kbuffer search found no special character (currently Z) in the kernel buffers.')
                        print('kbuffer search found no special character (currently Z) in the kernel buffers.')
                        print('The kbuf option requires a data stream that contains Zs')
                        print('You also want the target to read as much as it can from the kernel buffers, e.g., if multiple reads are used.')
                        SIM_break_simulation('error in kbuffer')    
                    return
                buf_size = (last_good - src) + 1 
                self.lgr.debug('Kbuffer updateBuffers, last_good addr 0x%x, buf_size %d' % (last_good, buf_size))
                if self.kbuf_len is None:
                    self.kbuf_len = buf_size
        
        
                self.buf_remain = self.kbuf_len
        
                if self.read_count > self.kbuf_len:
                    new_break = self.watching_addr + self.kbuf_len
                    self.lgr.debug('Kbuffer, count given in read syscall %d greater than buf size %d, set next break at 0x%x' % (self.read_count, self.kbuf_len, new_break))
                    SIM_run_alone(self.replaceHap, new_break)
                    self.watching_addr = new_break
                #SIM_break_simulation('tmp')
            else:
                ''' Not enough remaining... just assume same length. '''
                self.lgr.debug('Kbuffer not enough remaining buf_reamin is %s' % str(self.buf_remain))
                self.buf_remain = 0


    def writeHap(self, Dumb, third, forth, memory):
        ''' callback when user space buffer address is written'''
        if self.write_hap is None:
            return
        value = SIM_get_mem_op_value_le(memory)
        if self.data_watch is not None and self.data_watch.commence_with is not None:
            first = value & 0xff
            commence_1 = ord(self.data_watch.commence_with[0])
            self.lgr.debug('Kbuffer writeHap commence_1 0x%x value 0x%x first: 0x%x' % (commence_1, value, first))
            if commence_1 != first:
                return
            else:
                # do not wait for 2nd write, this is the 2nd write most likely
                self.hack_count = 2
        self.lgr.debug('Kbuffer writeHap addr 0x%x value 0x%x' % (memory.logical_address, value))
        if self.cpu.architecture != 'arm':
            eip = self.top.getEIP()
            if self.top.isWindows() and self.hack_count < 1:
                self.hack_count = self.hack_count + 1
                self.lgr.debug('Kbuffer writeHap skip first write.  Windows fu. eip: 0x%x' % eip)
            elif not self.mem_utils.isKernel(eip):
                self.lgr.debug('Kbuffer eip 0x%x not in kernel, skip' % eip)
            else:
                hap = self.write_hap
                SIM_run_alone(self.removeHap, hap)
                self.write_hap = None
    
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)

                if not self.top.isWindows():
                    esi = self.mem_utils.getRegValue(self.cpu, 'esi') 
                    src = esi 
                    self.lgr.debug('Kbuffer writeHap, eip 0x%x, esi 0x%x, instruct: %s cycle: 0x%x' % (eip, esi, instruct[1], self.cpu.cycles))
                    if self.kernel_cycle_of_write is None:
                        self.kernel_cycle_of_write = self.cpu.cycles - 1
                    self.updateBuffers(src)
                else:
                    self.top.stopAndGo(self.findWinBuf)
        else:
            hap = self.write_hap
            SIM_run_alone(self.removeHap, hap)
            self.write_hap = None
    
           
            #self.removeHap(None)
            #self.top.stopTrackIO()
            src = self.findArmBuf()
            #SIM_break_simulation('arm writeHap')

    def removeHap(self, hap, immediate=False):
        if hap is not None:
            self.context_manager.genDeleteHap(hap, immediate=immediate)

    def replaceHap(self, addr):
        if self.write_hap is not None:
            self.context_manager.genDeleteHap(self.write_hap)
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, addr, 1, 0)
            self.write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, None, proc_break, 'kbuffer_write')

    def readReturn(self, length):
        if self.buf_remain is None:
            self.lgr.debug('Kbuffer readReturn, no buf_remain set, skip it.')
            return
        self.buf_remain = self.buf_remain - length 
        self.lgr.debug('Kbuffer readReturn length %d, watching_addr was 0x%x, buf_remain now %d' % (length, self.watching_addr, self.buf_remain))
        if self.buf_remain <= 0:
            self.lgr.debug('Kbuffer got %d k buffers:' % len(self.kbufs))
            for addr in self.kbufs:
                self.lgr.debug('\t 0x%x' % addr)
            SIM_break_simulation('Final kbuf found for 2nd read.  TBD handle more reads!')

    def getKbuffers(self):
        return self.kbufs

    def getBufLength(self):
        return self.kbuf_len

    def getUserAddr(self):
        return self.user_addr

    def getUserCount(self):
        return self.user_count

    def getOrigBuf(self):
        return self.orig_buffer

    def getKernelCycleOfWrite(self):
        return self.kernel_cycle_of_write 

    def findWinBuf(self):
        SIM_run_alone(self.findWinBufAlone, None)

    def findWinBufAlone(self, dumb):
        ''' Find a windows kernel buffer.  Set context so we can keep the tracking breakpoints '''
        self.context_manager.setReverseContext() 
        self.lgr.debug('Kbuffer findWinBuf set reverse context: %r' % self.context_manager.isReverseContext())
        eip = self.top.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('Kbuffer findWinBuf instruct %s' % instruct[1])

        prev = self.cpu.cycles - 1 
        resimUtils.skipToTest(self.cpu, prev, self.lgr)
        eip = self.top.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        op2, op1 = decode.getOperands(instruct[1])
        self.lgr.debug('Kbuffer findWinBuf skipped back one, intruct: %s op1 is %s op2: %s' % (instruct[1], op1, op2))
        our_reg = op2
        if self.kernel_cycle_of_write is None:
            self.kernel_cycle_of_write = self.cpu.cycles - 1
        limit = 20
        gotit = False
        for i in range(limit):
            prev = self.cpu.cycles - 1 
            resimUtils.skipToTest(self.cpu, prev, self.lgr)
            eip = self.top.getEIP()
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('Kbuffer findWinBuf prev instruct %s' % instruct[1])
            op2, op1 = decode.getOperands(instruct[1])
            if instruct[1].startswith('mov') and op1 == our_reg:
                src = decode.getAddressFromOperand(self.cpu, op2, self.lgr)
                self.lgr.debug('Kbuffer findWinBuf got it, src: 0x%x' % src)
                self.updateBuffers(src)
                self.context_manager.clearReverseContext() 
                gotit = True
                SIM_continue(0) 
                break
        if not gotit:
            self.lgr.error('kbuffer findWinBufAlone failed to find buffer')
          
    def rmAllHaps(self, immediate=False):
        self.lgr.debug('kbuffer rmAllHaps')
        if self.count_write_hap is not None:
            hap = self.count_write_hap
            if immediate:
                self.removeHap(hap, immediate=True)
            else:
                SIM_run_alone(self.removeHap, hap) 
            self.write_hap = None
