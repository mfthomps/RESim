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
import decodePPC32
import decode
import resimUtils
import memUtils
'''
Track kernel buffers used with read/recv calls

Kernel buffer size is determined by looking for a fixed character (Z) following a backtrack
of the first write to the application read buffer.
'''
class Kbuffer():
    def __init__(self, top, cpu, context_manager, mem_utils, data_watch, lgr, commence=None, stop_when_done=False):
        self.context_manager = context_manager
        self.mem_utils = mem_utils
        self.data_watch = data_watch
        self.top = top
        self.cpu = cpu
        self.lgr = lgr
        self.watching_addr = None
        self.kbufs = []
        # in case buffer lengths vary, e.g., due to starting kbuf in mid-conversation.
        self.kbuf_len = []
        self.write_hap = None
        self.read_count = None
        self.buf_remain = None
        self.user_addr = None
        self.user_count = None
        self.orig_buffer = None
        self.kernel_cycle_of_write = None
        self.hack_count = 0
        self.tot_buf_size = 0
        self.stop_when_done = stop_when_done
        self.ass_backwards = False
        # cycle at which writeHap was hit, return here after stopping, which may take a cycle
        self.write_cycle = None
        self.fd = None
        self.tid = None

    def read(self, addr, count, fd):
        ''' syscall got a read call. '''
        self.lgr.debug('Kbuffer read addr 0x%x' % addr)
        if self.data_watch.hasCommenceWith():
            self.lgr.debug('Kbuffer read dataWatch still waiting on commence_with, do nothing')
            return 
        self.fd = fd
        phys = self.mem_utils.v2p(self.cpu, addr)
        self.tid = self.top.getTID()
 
        # TBD fix this
        if count == 0:
            self.lgr.debug('Kbuffer read count is zero.  TBD fix this')
            count = 100
        if self.watching_addr is None:
            # first buffer
            self.watching_addr = addr

            if phys is not None and phys != 0:
                #proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, addr, count, 0)
                
                break_num = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, phys, count, 0)
                self.write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, None, break_num, 'kbuffer_write')
                self.read_count = count
                self.lgr.debug('Kbuffer first read set write_hap on 0x%x phys 0x%x, count 0x%x' % (addr, phys, count))
            else:
                 self.lgr.error('Kbuffer read read phys of addr 0x%x is None' % addr)
                 return
            self.user_addr = addr
            self.user_count = count
            self.orig_buffer = self.mem_utils.readBytes(self.cpu, addr, count)
        elif self.buf_remain is not None:
            self.lgr.debug('Kbuffer read buf_remain is %d count %d' % (self.buf_remain, count))
            if self.buf_remain < count:
                new_addr = addr + self.buf_remain
                self.watching_addr = new_addr
                #proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, new_addr, 1, 0)
                #self.write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, None, proc_break, 'kbuffer_write')
                break_num = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, phys, count, 0)
                self.write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, None, break_num, 'kbuffer_write')
                self.read_count = count
                self.lgr.debug('Kbuffer read, set new hap at new_addr 0x%x phys 0x%x read_count %d' % (new_addr, phys, count))
                self.data_watch.registerHapForRemoval(self)

    def gotBufferCallback(self, buf_addrs):
        ''' Not yet used, would need to stop simulation'''
        if len(buf_addrs) == 0:
            self.lgr.error('Kbuffer gotBufferCallback called with no buffers')
        else:
            src = buf_addrs[0]
            self.lgr.debug('Kbuffer gotBufferCallback, src 0x%x' % src)
            self.updateBuffers(src)

    def findArmBuf(self, dumb=None):
        # Find kernel buffers for arm processors.  First skip to the cycle that got us here, which is likely -1 from where we are
        self.top.skipToCycle(self.write_cycle, disable=True, cpu=self.cpu)
        eip = self.top.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('Kbuffer findArmBuf eip 0x%x  cycle: 0x%x, is ARM, expect a str: %s' % (eip, self.cpu.cycles, instruct[1]))
        if instruct[1].startswith('str') or instruct[1].startswith('stp'):
            op2, op1 = decodeArm.getOperands(instruct[1])
            self.lgr.debug('Kbuffer findArmBuf op1 is %s' % op1)
            our_reg = op1
            #self.top.revRegSrc(op1, kernel=True, callback=self.gotBufferCallback, taint=False)
            limit = 20
            gotone = False
            for i in range(limit):
                prev = self.cpu.cycles - 1 
                self.top.skipToCycle(prev, cpu=self.cpu, disable=True)
                eip = self.top.getEIP()
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('findArmBuf pc: 0x%x instruct: %s' % (eip, instruct[1]))
                if instruct[1].startswith('ldm') or instruct[1].startswith('ldr') or instruct[1].startswith('ldp'):
                    if instruct[1].startswith('ldp'):
                        op3, op2, op1 = decodeArm.getOperands3(instruct[1])
                    else:
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
                    elif instruct[1].startswith('ldp'):
                        if op1 == our_reg:
                            value = decodeArm.getAddressFromOperand(self.cpu, op3, self.lgr, after=True)
                        else:
                            self.lgr.debug('findARmBuf ldp not our reg, skip it')
                            continue
                    else:
                        ''' assume ldr '''
                        if op1 == our_reg:
                            value = decodeArm.getAddressFromOperand(self.cpu, op2, self.lgr, after=False)
                                
                        else:
                            self.lgr.debug('findARmBuf not our reg, skip it')
                            continue
                    self.lgr.debug('findArmBuf buf found at 0x%x' % value)
                    if self.kernel_cycle_of_write is None:
                        # before kernel starts reading buffer
                        self.kernel_cycle_of_write = self.cpu.cycles - 1
                        self.lgr.debug('findArmBuf buf kernel_cycle_of_write is 0x%x' % self.kernel_cycle_of_write)
                    self.updateBuffers(value)
                    gotone = True
                    break
            if not gotone:
                self.lgr.error('findArmBuf failed to find instruction sequence')
        else:
            self.lgr.error('findArmBuf, expected str instruction, got %s' % instruct[1])
            
    def findPPCBuf(self, dumb=None):
        # Find kernel buffers for ppc32 processors.  First skip to the cycle that got us here, which is likely -1 from where we are
        self.top.skipToCycle(self.write_cycle, disable=True)
        eip = self.top.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('Kbuffer FindPPCBuf eip 0x%x  cycle: 0x%x, is PPC, expect a st2: %s' % (eip, self.cpu.cycles, instruct[1]))
        if instruct[1].startswith('stw') or instruct[1].startswith('stb'):
            op2, op1 = decodeArm.getOperands(instruct[1])
            self.lgr.debug('Kbuffer FindPPCBuf op1 is %s' % op1)
            our_reg = op1
            #self.top.revRegSrc(op1, kernel=True, callback=self.gotBufferCallback, taint=False)
            limit = 20
            gotone = False
            for i in range(limit):
                prev = self.cpu.cycles - 1 
                self.top.skipToCycle(prev, cpu=self.cpu, disable=True)
                eip = self.top.getEIP()
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('FindPPCBuf pc: 0x%x instruct: %s' % (eip, instruct[1]))
                if instruct[1].startswith('lw'):
                    op2, op1 = decodeArm.getOperands(instruct[1])
                    writeback = False
                    if op1 == our_reg:
                        value = decodePPC32.getAddressFromOperand(self.cpu, op2, self.lgr, after=True)
                    else:
                        self.lgr.debug('findPPCBuf lw not our reg, skip it')
                        continue
                    self.lgr.debug('FindPPCBuf buf found at 0x%x' % value)
                    if self.kernel_cycle_of_write is None:
                        # before kernel starts reading buffer
                        self.kernel_cycle_of_write = self.cpu.cycles - 1
                        self.lgr.debug('FindPPCBuf buf kernel_cycle_of_write is 0x%x' % self.kernel_cycle_of_write)
                    self.updateBuffers(value)
                    gotone = True
                    break
            if not gotone:
                self.lgr.error('FindPPCBuf failed to find instruction sequence')
        else:
            self.lgr.error('FindPPCBuf, expected str instruction, got %s' % instruct[1])

    def updateBuffers(self, src):
        if len(self.kbuf_len) > 0 and src > self.kbufs[-1] and src < (self.kbufs[-1]+self.kbuf_len[-1]):
            ''' The read is from the same kernel buffer used on the previous read.'''
            self.lgr.debug('Kbuffer updateBuffers read from previous kernel buffer 0x%x' % self.kbufs[-1])
            kbuf_remaining = (self.kbufs[-1] + self.kbuf_len[-1]) - src + 1
            if self.read_count > kbuf_remaining:
                ''' change break to write of first byte from next buffer '''
                new_break = self.watching_addr + kbuf_remaining
                self.lgr.debug('Kbuffer updateBuffers not first buffer, count given in read syscall %d greater than end of remaining kbuf %d, set next break at 0x%x' % (self.read_count, 
                            kbuf_remaining, new_break))
                SIM_run_alone(self.replaceHap, new_break)
                self.watching_addr = new_break

        else:  
            if len(self.kbuf_len) > 0:
                self.lgr.debug('Kbuffer updateBuffers adding kbuf of 0x%x, previous kbuf_len is %s' % (src, str(self.kbuf_len[-1])))
            else:
                self.lgr.debug('Kbuffer updateBuffers adding kbuf of 0x%x, this is the first, so we have no length' % (src))
            self.kbufs.append(src)
            print('adding kbuf 0x%x' % src)
            if len(self.kbuf_len) == 0 or (self.buf_remain is None or self.buf_remain > 100):
                # TBD this may need to be adjustable data files that require specific fields to force consumption of the entire kernel buffer.
                # Better to parse the primer file  in writeData to identify the non-special characters and allow for them.
                max_bad = 300
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
                        if last_good is not None:
                            size = (last_good - src) + 1
                            self.lgr.debug('bad count now %d buf size %d' % (bad_count, size))
                        if bad_count > max_bad:
                            done = True
                            break
                    else:
                        last_good = cur_addr
                        bad_count = 0
                    cur_addr += 1
                if last_good is None:
                    if len(self.kbuf_len) == 0:
                        self.lgr.error('kbuffer search found no special character (currently Z) in the kernel buffers.')
                        print('kbuffer search found no special character (currently Z) in the kernel buffers.')
                        print('The kbuf option requires a data stream that contains Zs')
                        print('You also want the target to read as much as it can from the kernel buffers, e.g., if multiple reads are used.')
                        SIM_break_simulation('error in kbuffer')    
                    return
                buf_size = (last_good - src) + 1 
                self.lgr.debug('Kbuffer updateBuffers, last_good addr 0x%x, buf_size %d' % (last_good, buf_size))
                #if self.kbuf_len is None:
                #    self.kbuf_len = buf_size
                self.kbuf_len.append(buf_size)
                self.tot_buf_size = self.tot_buf_size + buf_size
        
                self.buf_remain = buf_size
       
                 
                if self.read_count > self.tot_buf_size:
                    new_break = self.watching_addr + buf_size
                    self.lgr.debug('Kbuffer updateBuffers, count given in read syscall %d greater than cumulative buf size %d, set next break at 0x%x' % (self.read_count, self.tot_buf_size, new_break))
                    SIM_run_alone(self.replaceHap, new_break)
                    self.watching_addr = new_break
                elif self.stop_when_done:
                    self.lgr.debug('Kbuffer updateBuffers got all bufs, and told to stop')
                    SIM_break_simulation('Kbuffer updateBuffers got all bufs, and told to stop')
            else:
                ''' Not enough remaining... just assume same length. '''
                self.lgr.debug('Kbuffer not enough remaining buf_reamin is %s' % str(self.buf_remain))
                self.buf_remain = 0


    def writeHap(self, Dumb, the_object, break_num, memory):
        ''' callback when user space buffer address is written'''
        self.lgr.debug('Kbuffer writeHap') 
        if self.write_hap is None:
            return
        value = memUtils.memoryValue(self.cpu, memory)
        '''
        if self.data_watch is not None and self.data_watch.commence_with is not None:
            first = value & 0xff
            commence_1 = ord(self.data_watch.commence_with[0])
            self.lgr.debug('Kbuffer writeHap commence_1 0x%x value 0x%x first: 0x%x' % (commence_1, value, first))
            if commence_1 != first:
                hap = self.write_hap
                SIM_run_alone(self.removeHap, hap)
                self.write_hap = None
                self.watching_addr = None
                return
            else:
                # do not wait for 2nd write, this is the 2nd write most likely
                self.hack_count = 2
        '''
        eip = self.top.getEIP()
        tid = self.top.getTID()
        self.lgr.debug('Kbuffer writeHap this tid:%s watching tid:%s addr 0x%x physical 0x%x, value 0x%x watching_addr: 0x%x eip: 0x%x cycle: 0x%x' % (tid, self.tid, 
                memory.logical_address, memory.physical_address, value, self.watching_addr, eip, self.cpu.cycles))
        self.write_cycle = self.cpu.cycles
        if self.cpu.architecture.startswith('arm'):
            # ARM
            hap = self.write_hap
            SIM_run_alone(self.removeHap, hap)
            self.write_hap = None
            
            if memory.logical_address != self.watching_addr:
                self.lgr.debug('Kbuffer writeHap seems ass backwards')
                self.ass_backwards = True 
           
            #self.removeHap(None)
            #self.top.stopTrackIO()
            #src = self.findArmBuf()
            SIM_run_alone(self.top.stopAndCall, self.findArmBuf)
            #SIM_break_simulation('arm writeHap')
        elif self.cpu.architecture == 'ppc32':
            # PPC
            hap = self.write_hap
            SIM_run_alone(self.removeHap, hap)
            self.write_hap = None
            
            if memory.logical_address != self.watching_addr:
                self.lgr.debug('Kbuffer writeHap seems ass backwards')
                self.ass_backwards = True 
           
            SIM_run_alone(self.top.stopAndCall, self.findPPCBuf)
        else:
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


    def removeHap(self, hap, immediate=False):
        if hap is not None:
            self.context_manager.genDeleteHap(hap, immediate=immediate)

    def replaceHap(self, addr):
        self.lgr.debug('Kbuffer replaceHap')
        if self.write_hap is not None:
            self.context_manager.genDeleteHap(self.write_hap, immediate=True)
        phys = self.mem_utils.v2p(self.cpu, addr)
        proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, phys, 1, 0)
        self.write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, None, proc_break, 'kbuffer_write')
        self.lgr.debug('Kbuffer replaceHap set write hap on 0x%x' % addr) 
        self.top.continueForward()

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
        self.top.skipToCycle(prev, cpu=self.cpu, disable=True)
        eip = self.top.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        op2, op1 = decode.getOperands(instruct[1])
        self.lgr.debug('Kbuffer findWinBuf skipped back one, intruct: %s op1 is %s op2: %s' % (instruct[1], op1, op2))
        our_reg = op2
        limit = 20
        gotit = False
        for i in range(limit):
            prev = self.cpu.cycles - 1 
            self.top.skipToCycle(prev, cpu=self.cpu, disable=True)
            eip = self.top.getEIP()
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('Kbuffer findWinBuf prev instruct %s  cycles: 0x%x' % (instruct[1], self.cpu.cycles))
            op2, op1 = decode.getOperands(instruct[1])
            if instruct[1].startswith('mov') and op1 == our_reg:
                src = decode.getAddressFromOperand(self.cpu, op2, self.lgr)
                self.lgr.debug('Kbuffer findWinBuf got it, src: 0x%x cycle: 0x%x' % (src, self.cpu.cycles))
                self.updateBuffers(src)
                self.context_manager.clearReverseContext() 
                gotit = True
                if self.kernel_cycle_of_write is None:
                    self.kernel_cycle_of_write = self.cpu.cycles - 1
                SIM_continue(0) 
                break
        if not gotit:
            self.lgr.error('Kbuffer findWinBufAlone failed to find buffer')
          
    def rmAllHaps(self, immediate=False):
        self.lgr.debug('kbuffer rmAllHaps')

    def gotCommence(self):
        # DataWatch got the commence string.  We need to back-up pre syscall and redo the read/recv 
        self.lgr.debug('Kbuffer gotCommence, do stopAndCall')
        SIM_run_alone(self.top.stopAndCall, self.restartRead)

    def restartRead(self, dumb=None): 
        frame, cycle = self.top.getPreviousEnterCycle() 
        before_read = cycle - 1
        self.lgr.debug('Kbuffer restartRead skip to cycle 0x%x' % before_read)
        self.top.skipToCycle(before_read, disable=True)
        syscall_manager = self.top.getSyscallManager()
        # allow syscalls to see entries they previously saw
        syscall_manager.clearSyscallCycles()
        self.lgr.debug('Kbuffer restartRead did skip to 0x%x , go' % self.cpu.cycles)
        SIM_run_alone(SIM_continue, 0)        

    def getFD(self):
        return self.fd

    def getTID(self):
        return self.tid
