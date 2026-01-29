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
import dataWatch
import armCond
import memUtils
'''
Detect and watch regx searches.
Preliminary, tested with arm and one boost library
The classmethod should be invoked rather than the constructor.  It will
return None if this does not look like a regx handler.
This module will generate watch marks on references to pointers to characters found as
part of byte map lookups.  The dataWatch module manages watch marks for the initial
character lookup.
'''
match_funs = ['charLookup', 'charLookupX', 'charLookupY']
def findRegValue(reg, instruct_history, decode, mem_utils, cpu, lgr):
        retval = None
        done = False
        while not done:
            if len(instruct_history) == 0:
                lgr.debug('reWatch, findRegValue no instructions in history, done')
                break
            instruct = instruct_history.pop()
            lgr.debug('reWatch, findRegValue instruct %s' % instruct[1])
            if instruct[1].startswith('ldr'):
                lgr.debug('reWatch, findRegValue is ldr')
                op2, op1 = decode.getOperands(instruct[1])
                if op1 == reg:
                    lgr.debug('reWatch, findRegValue our reg, getaddr from %s' % op2)
                    cmp_addr = decode.getAddressFromOperand(cpu, op2, lgr)
                    if cmp_addr is not None:
                        if instruct[1].startswith('ldrb'):
                            lgr.debug('reWatch, findRegValue got cmp_addr 0x%x' % cmp_addr)
                            retval = mem_utils.readByte(cpu, cmp_addr)
                        else:
                            lgr.debug('reWatch, findRegValue only ldrb handled for now')
                    break
                else:
                    lgr.debug('reWatch, findRegValue op1 %s not reg %s' % (op1, reg))
        return retval

class REWatch(object):
    def __init__(self, addr, ip, decode, cpu, pid, mem_utils, context_manager, watch_marks, top, lgr, base_val, match_type):
        self.addr = addr
        self.ip = ip
        self.decode = decode
        self.cpu = cpu
        self.pid = pid
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.watch_marks = watch_marks
        self.top = top
        self.lgr = lgr
        self.base_val = base_val
        self.match_type = match_type
        self.map_start = []
        self.map_length = []
        self.map_read_hap = []
        self.result_read_hap = {}
        self.result_block_hap = {}
        self.result_watch_list = []
        self.hit_list = []
        self.char_addr_list = []
        self.search_chars = None
        self.getCharLookup(base_val)
        self.setMapBreakRange()
        msg = 'REWatch Base value of char map is 0x%x %s' % (base_val, self.getSearchChars())
        self.lgr.debug(msg)


    @classmethod
    def isCharLookup(cls, addr, ip, instruct, decode, cpu, pid, mem_utils, context_manager, watch_marks, top, lgr):
        retval = None
        op2, op1 = decode.getOperands(instruct[1])
        # distinguish different function signatures
        match_type = 0
        #lgr.debug('reWatch isCharLookup evaluate hit addr 0x%x ip: 0x%x %s' % (addr, ip, instruct[1]))
        ''' TBD generalize for x86 and ppc'''
        if decode.isLDRB(cpu, instruct[1]) and decode.isReg(op1):
            our_reg = op1
            next_ip = ip + instruct[0]
            next_instruct = SIM_disassemble_address(cpu, next_ip, 1, 0)
            #lgr.debug('reWatch isCharLookup is ldrb our reg is %s' % our_reg)
            bail_count = 0
            bail_max = 3
            instruct_history = []
            while bail_count < bail_max:
                #lgr.debug('reWatch isCharLookup ip: 0x%x bail_count %d %s' % (next_ip, bail_count, next_instruct[1]))
                op2, op1 = decode.getOperands(next_instruct[1])
                if op1 is not None and decode.isReg(op1) and decode.isAdd(cpu, next_instruct[1]) \
                          and our_reg in op2 and ',' in op2:
                    lgr.debug('reWatch isCharLookup may be character table lookup at 0x%x' % next_ip)
                    parts = op2.split(',')
                    base_reg = parts[0] 
                    next_ip = next_ip + next_instruct[0]
                    next_instruct = SIM_disassemble_address(cpu, next_ip, 1, 0)
      
                    lgr.debug('reWatch isCharLookup next instruct is %s' % next_instruct[1])
                    next_op2, next_op1 = decode.getOperands(next_instruct[1])
                    if decode.isLDRB(cpu, next_instruct[1]) and op1 in next_op2:
                        ''' TBD generalize, and add support for x86'''
                        base_val = mem_utils.getRegValue(cpu, base_reg) 
                        inbracket = decode.inBracket(next_op2)
                        if inbracket is not None and ',' in inbracket:
                            offset_str = inbracket.split(',')[1]
                            offset = decode.getValue(offset_str, cpu)
                            base_val = base_val + offset
                            if match_type == 0:
                                fun = top.getFunName(ip)
                                if fun is None:
                                    lgr.debug('reWatch isCharLookup no fun name was match type 0, assign match type 2  TBD???')
                                    match_type = 2

                            return cls(addr, ip, decode, cpu, pid, mem_utils, context_manager, watch_marks, top, lgr, base_val, match_type)
                    break
                else:
                    if next_instruct[1].startswith('cmp'):
                        op2, op1 = decode.getOperands(next_instruct[1])
                        #lgr.debug('reWatch isCharLookup is a cmp')
                        if op2 in ['0', '#0','#0x0']:
                            compare_value = findRegValue(op1, instruct_history, decode, mem_utils, cpu, lgr)
                            if compare_value is not None:
                                #lgr.debug('reWatch isCharLookup got compare_value 0x%x' % compare_value)
                                branch_ip = next_ip + next_instruct[0]
                                branch_instruct = SIM_disassemble_address(cpu, branch_ip, 1, 0)
                                if branch_instruct[1].startswith('bne'): 
                                    if compare_value == 0:
                                        next_ip = branch_ip + next_instruct[0]
                                        next_instruct = SIM_disassemble_address(cpu, next_ip, 1, 0)
                                    else:
                                        dumb, next_ip_str = decode.getOperands(branch_instruct[1])
                                        next_ip = int(next_ip_str, 16)
                                        next_instruct = SIM_disassemble_address(cpu, next_ip, 1, 0)
                                    #lgr.debug('reWatch isCharLookup is bne')
                                elif branch_instruct[1].startswith('beq'): 
                                    if compare_value == 0:
                                        dumb, next_ip_str = decode.getOperands(branch_instruct[1])
                                        next_ip = int(next_ip_str, 16)
                                        next_instruct = SIM_disassemble_address(cpu, next_ip, 1, 0)
                                    else:
                                        next_ip = branch_ip + next_instruct[0]
                                        next_instruct = SIM_disassemble_address(cpu, next_ip, 1, 0)
                                    #lgr.debug('reWatch isCharLookup is beq')
                                else:
                                    #lgr.debug('reWatch isCharLookup not branch instruction %s' % branch_instruct[1])
                                    pass
                                fun = top.getFunName(ip)
                                if fun is None:
                                    lgr.debug('reWatch isCharLookup no fun name, assign match type 2')
                                    match_type = 2
                                else:
                                    match_type = 1
                            else:
                                lgr.debug('reWatch isCharLookup failed to find reg value')
                                break
                        else:
                            #lgr.debug('reWatch isCharLookup compare op2 not zero %s' % op2)
                            break
                    else:                                     
                        instruct_history.append(next_instruct)
                        next_ip = next_ip + next_instruct[0]
                        next_instruct = SIM_disassemble_address(cpu, next_ip, 1, 0)
                        bail_count += 1
        return retval


    def getCharLookup(self, base_val):
        outstring = ''
        last_index = None
        in_a_row = 0
        first_entry = ''
        for i in range(256):
            addr = base_val + i
            val = self.mem_utils.readByte(self.cpu, addr)
            if val != 1:
                hexval = '0x%x' % i
                if i < 127 and i > 0x1f:
                    cval = '(%s)' % chr(i)
                else:
                    cval = ''
                if last_index is not None and last_index == i-1:
                    in_a_row = in_a_row + 1
                    last_entry = hexval+cval
                else:
                    first_entry = hexval+cval
                    in_a_row = 1
                    self.map_start.append(addr)
                last_index = i
            else:
                if in_a_row > 0:
                    if in_a_row > 1:
                        outstring = outstring+' '+first_entry+'-'+last_entry
                    else:
                        outstring = outstring+' '+first_entry
                    self.map_length.append(in_a_row)
                in_a_row = 0
        if in_a_row > 0:
            if in_a_row > 1:
                outstring = outstring+' '+first_entry+'-'+last_entry
            else:
                outstring = outstring+' '+first_entry
            self.map_length.append(in_a_row)
        self.search_chars = outstring

    def getMemSomething(self, addr):
        retval = None
        st = self.top.getStackTraceQuiet(max_frames=2, max_bytes=1000)
        if st is None:
            self.lgr.debug('reWatch getMemSomething handleCharLookup, stack not found???')
        else:
            frames = st.getFrames(2)
            f = frames[1]
            self.lgr.debug('reWatch getMemSomething addr 0x%x using 2nd frame frame %s' % (addr, f.dumpString()))
            if f.ret_addr is None:
                self.lgr.error('reWatch getMemSomething f.ret_addr is None')
            else:
                fun = match_funs[self.match_type]
                mem_something = dataWatch.MemSomething(fun, f.fun_addr, addr, f.ret_addr, None, None, None, f.ip, None, None, None)
                mem_something.re_watch = self
                retval =  mem_something 
                #self.lgr.error('reWatch getMemSomething returning mem_something')
                
        return retval

    def setMapBreakRange(self, i_am_alone=False):
        #self.lgr.debug('reWatch setMapBreakRange')
        ''' Set breakpoints for each range defined in self.map_start and self.map_length '''
        context = self.context_manager.getRESimContext()
        num_existing_haps = len(self.map_read_hap)
        for index in range(num_existing_haps, len(self.map_start)):
            if self.map_start[index] is None:
                #self.lgr.debug('REMap setMapBreakRange index %d is 0' % index)
                self.map_read_hap.append(None)
                continue
            break_num = self.context_manager.genBreakpoint(context, Sim_Break_Linear, Sim_Access_Read, self.map_start[index], self.map_length[index], 0)
            end = self.map_start[index] + self.map_length[index] 
            eip = self.top.getEIP(self.cpu)
            #self.lgr.debug('REMap setMapBreakRange eip: 0x%x Adding breakpoint %d for %x-%x length %x index now %d number of read_haps was %d  alone? %r cpu context:%s' % (eip, break_num, self.map_start[index], end, 
            #    self.map_length[index], index, len(self.map_read_hap), i_am_alone, self.cpu.current_context))
            self.map_read_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.mapReadHap, index, break_num, 'reWatch'))
            #self.lgr.debug('REMap back from set break range')
            
        if len(self.map_start) != len(self.map_read_hap):
            self.lgr.error('reWatch setMapBreakRange start len is %d while read_hap is %d' % (len(self.map_start), len(self.map_read_hap)))

    def stopMapWatch(self, immediate=False):
        #self.lgr.debug('reWatch stopWatch immediate: %r len of start is %d len of read_hap: %d' % (immediate, len(self.map_start), len(self.map_read_hap)))
        for index in range(len(self.map_start)):
            if self.map_start[index] is None:
                continue
            if index < len(self.map_read_hap):
                if self.map_read_hap[index] is not None:
                    #self.lgr.debug('reWatch stopWatch delete hap %d' % self.map_read_hap[index])
                    self.context_manager.genDeleteHap(self.map_read_hap[index], immediate=immediate)
            else:
                #self.lgr.debug('reWatch stopWatch index %d not in read_hap len is %d ' % (index, len(self.map_read_hap)))
                pass
        #self.lgr.debug('REMap stopWatch removed read haps')
        del self.map_read_hap[:]
        if self.result_block_hap is not None:
            self.context_manager.genDeleteHap(self.result_block_hap)
            self.result_block_hap = None

    def mapReadHap(self, index, an_object, breakpoint, memory):
        addr = memory.logical_address
        offset = addr - self.base_val
        self.hit_list.append(offset)
        #self.lgr.debug('reWatch hit address 0x%x offset 0x%x' % (addr, offset)) 

    def getSearchChars(self):
        return self.search_chars

    def getFoundChars(self):
        retval = []
        for offset in self.hit_list:
            h = '0x'+hex(offset)
            if offset < 127 and offset > 0x1f:
                val = h+'('+chr(offset)+')'
            else:
                val = h
            retval.append(val)
        return retval

    def resultBlockHap(self, index, an_object, breakpoint, memory):
        ''' invoked when result block is written to '''
        value = memUtils.memoryValue(self.cpu, memory)
        addr = memory.logical_address
        if value in self.char_addr_list and addr not in self.result_watch_list:
            self.lgr.debug('reWatch resultBlock wrote 0x%x to resultBlock addr 0x%x, watch addr' % (value, addr))
            self.result_watch_list.append(addr)
            context = self.context_manager.getRESimContext()
            break_num = self.context_manager.genBreakpoint(context, Sim_Break_Linear, Sim_Access_Read, addr, self.mem_utils.WORD_SIZE, 0)
            self.result_read_hap[addr] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.resultReadHap, addr, break_num, 'reResultWatch')
        elif addr in self.result_watch_list:
            ''' assume over-write or free? remove the watch '''
            
            if addr in self.result_read_hap:
                self.lgr.debug('reWatch resultBlockHap assume over-write or free? remove the watch on addr 0x%x' % addr)
                SIM_run_alone(self.stopResultWatch,addr)

    def watchResultBlock(self):
        if self.result_block_hap is not None and self.return_ptr is not None:
            ''' TBD wag '''
            start = self.return_ptr + 20
            length = 80
            self.lgr.debug('reWatch watchResultBlock set write hap on 0x%x %d bytes' % (start, length))
            context = self.context_manager.getRESimContext()
            break_num = self.context_manager.genBreakpoint(context, Sim_Break_Linear, Sim_Access_Write, start, length, 0)
            self.result_block_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.resultBlockHap, None, break_num, 'reWatchResultBlock')

    def watchCharReference(self, ret_addr):
        self.lgr.debug('reWatch watchCharReference')
        self.return_ptr = self.mem_utils.readPtr(self.cpu, ret_addr)
        if self.return_ptr is None:
            self.lgr.debug('reWatch watchCharReference got none reading reaturn_ptr from 0x%x' % ret_addr)
            return
        found_ptr = self.mem_utils.readPtr(self.cpu, self.return_ptr)
        if found_ptr is None:
            self.lgr.debug('reWatch watchCharReference got none reading found_ptr from 0x%x' % self.return_ptr)
            return
        length = found_ptr - self.addr
        self.lgr.debug('reWatch watchCharReference length %d' % length)
        if length > 10000:
            self.lgr.error('reWatch watchCharReference unexpected length %d, bail' % length)
            return
        for i in range(length):
            char_addr = self.addr + i
            char_at_i = self.mem_utils.readByte(self.cpu, char_addr)
            for hit in self.hit_list:
                if hit == char_at_i:
                    self.lgr.debug('reWatch watchCharReference found match at off %d into string' % i)
                    self.lgr.debug('reWatch watchCharReference look for pointer to char addr 0x%x' % char_addr)
                    self.char_addr_list.append(char_addr)
                    '''
                    for j in range(80):
                        ptr_addr = j*self.mem_utils.WORD_SIZE + return_ptr               
                        points_to = self.mem_utils.readPtr(self.cpu, ptr_addr)
                        #self.lgr.debug('check ptr_addr 0x%x points to 0x%x' % (ptr_addr, points_to))
                        if points_to == (char_addr+1):
                            self.lgr.debug('DING DING DING 0x%x' % char_addr)
                    '''
        self.watchResultBlock() 

    def setResultBreakRange(self, i_am_alone=False):
        #self.lgr.debug('reWatch setResultBreakRange')
        ''' Set breakpoints for each range defined in self.result_start and self.result_length '''
        context = self.context_manager.getRESimContext()
        for addr in self.result_watch_list:
            break_num = self.context_manager.genBreakpoint(context, Sim_Break_Linear, Sim_Access_Read, addr, self.mem_utils.WORD_SIZE, 0)
            self.result_read_hap[addr] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.resultReadHap, addr, break_num, 'reResultWatch')
            #self.lgr.debug('REMap back from set break range')

    def stopResultWatch(self, addr):
        if addr in self.result_read_hap:
            self.context_manager.genDeleteHap(self.result_read_hap[addr])
            del self.result_read_hap[addr]

    def stopResultWatchAll(self, immediate=False):
        for addr in self.result_read_hap:
            self.context_manager.genDeleteHap(self.result_read_hap[addr], immediate=immediate)

        self.result_read_hap = {}

        self.watchResultBlock()

    def resultReadHap(self, addr, an_object, breakpoint, memory):
        if addr not in self.result_read_hap:
            return
        cur_pid = self.top.getPID()
        if cur_pid != self.pid:
            self.lgr.debug('reWatch resultReadHap wrong pid, to %d wanted %d' % (cur_pid, self.pid))
            return
        addr = memory.logical_address
        ptr = self.mem_utils.readPtr(self.cpu, addr)
        if ptr is not None:
            value = self.mem_utils.readByte(self.cpu, ptr)
            if value is not None:
                self.watch_marks.charPtrMark(addr, ptr, value)
                self.lgr.debug('reWatch resultReadHap hit 0x%x ptr to 0x%x value 0x%x' % (addr, ptr, value))
            else:
                self.lgr.debug('reWatch resultReadHap, got None reading ptr 0x%x from addr 0x%x, TBD basis for removing hap?' % (ptr, addr))
        else:
            self.lgr.debug('reWatch resultReadHap, got None reading addr 0x%x, TBD basis for removing hap?' % addr)
