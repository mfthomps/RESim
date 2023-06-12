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
import resimUtils
import winSocket
class ParamRefTracker():
        ''' Track kernel references to user space during a system call '''        
        def __init__(self, rsp, rcx, rdx, r8, r9, mem_utils, task_utils, cpu, call_name, lgr):
            ''' will include rsp rcx, rdx, r8, r9 '''
            self.mem_utils = mem_utils
            self.task_utils = task_utils
            self.cpu = cpu
            self.start_cycle = cpu.cycles
            self.call_name = call_name
            self.lgr = lgr
            self.rcx = rcx
            self.rdx = rdx
            self.r8 = r8
            self.r9 = r9
            self.rsp = rsp
            self.base_params = {}
            value = self.mem_utils.readWord32(self.cpu, rcx)
            if value is not None:
                self.base_params['rcx'] = rcx
            value = self.mem_utils.readWord32(self.cpu, rdx)
            if value is not None:
                self.base_params['rdx'] = rdx
            value = self.mem_utils.readWord32(self.cpu, r8)
            if value is not None:
                self.base_params['r8'] = r8
            value = self.mem_utils.readWord32(self.cpu, r9)
            if value is not None:
                self.base_params['r9'] = r9
            self.base_params['rsp1'] = rsp+0x28
            self.base_params['rsp2'] = rsp+0x30
            self.base_params['rsp3'] = rsp+0x38
            self.base_params['rsp4'] = rsp+0x40
            if self.call_name == 'DeviceIoControlFile':
                ioctl_op_map = winSocket.getOpMap()
                operation = self.mem_utils.readWord32(self.cpu, self.base_params['rsp2']) & 0xffffffff
                if operation in ioctl_op_map:
                    self.call_name = ioctl_op_map[operation]
                
            self.other_addrs = {}
            self.refs = []
            self.wrote_values = {}
            self.wrote_sequence = 0
            self.prev_wrote_addr = None
            self.read_sequence = 0
            self.prev_read_addr = None
            self.pid_thread = self.task_utils.getPidAndThread()

        def toString(self):
            retval = 'call: %s rcx: 0x%x rdx: 0x%x r8: 0x%x r9: 0x%x sp: 0x%x cycles: 0x%x\n' % (self.call_name, self.rcx, self.rdx, self.r8, self.r9, self.rsp, self.start_cycle)
            index = 1
            for reference in self.refs:
                retval = '%s \t%d %s\n' % (retval, index, reference.toString())
                index = index+1
            retval = retval + '\nWrote:\n'
            for addr in self.wrote_values:
                reference = self.wrote_values[addr]
                retval = '%s \t%d %s\n' % (retval, index, reference.toString())
                index = index+1
            return retval
            

        class ParamRef():
            def __init__(self, addr, operator, value, hexstring, other_ptr, size, best_base, best_base_delta, ref_of_base):
                self.addr = addr
                self.operator = operator
                self.hexstring = hexstring
                self.value = value
                self.other_ptr = other_ptr
                self.size = size
                self.best_base = best_base
                self.best_base_delta = best_base_delta
                self.ref_of_base = ref_of_base

            def hackEncode(self, the_bytes):
                if resimUtils.isPrintable(the_bytes, ignore_zero=True):
                    retval = ''
                    for b in the_bytes:
                        if b > 0:
                           c = chr(b)
                           retval = retval + c
                else:
                    retval = the_bytes
                return retval

            def toString(self):
                if self.operator == 'read':
                    if len(self.value) > 24:
                       hexs = self.hackEncode(self.value)
                    else:
                       hexs = self.hexstring
                else:
                       hexs = self.hexstring
                
                if type(self.best_base) is str:
                    retval = 'addr: 0x%x %s: %s size: %d best_base: %s  best_base_delta: 0x%x' % (self.addr, self.operator, hexs, self.size, self.best_base, self.best_base_delta)
                else:
                    retval = 'addr: 0x%x %s: %s size: %d best_base: 0x%x  best_base_delta: 0x%x' % (self.addr, self.operator, hexs, self.size, self.best_base, self.best_base_delta)
                    retval = self.ref_of_base.toString(start_string=retval)
                return retval

        class OtherRef():
            ''' Represents a pointer found relative to some other base, which could be a register or another OtherRef '''
            def __init__(self, ptr, base, offset, ref_of_base, lgr):
                ''' the pointer value that was read relative to some other base '''
                self.ptr = ptr
                ''' names the other base '''
                self.base = base
                ''' offset from that other base '''
                self.offset = offset
                ''' The reference (OtherRef) associated with that base '''
                self.ref_of_base = ref_of_base
                self.lgr = lgr

            def toString(self, start_string=''):
                retval = start_string
                done = False
                cur_ref = self
                while not done:  
                    if type(cur_ref.base) is str:
                        entry = 'ptr 0x%x base %s offset 0x%x' % (cur_ref.ptr, cur_ref.base, cur_ref.offset)
                        done = True
                        retval = retval + ' '+entry
                    else:
                        entry = 'ptr 0x%x base 0x%x offset 0x%x' % (cur_ref.ptr, cur_ref.base, cur_ref.offset)
                        retval = retval + ' '+entry
                        cur_ref = cur_ref.ref_of_base 
                return retval

        def getBestBase(self, addr):
            best_base_delta = None
            best_base_of_base = None
            best_base_of_base_delta = None
            best_base = None
            #self.lgr.debug('\tgetBestBase for 0x%x' % addr)
            for base in self.base_params:
                #self.lgr.debug('\t\tgetBestBase compare 0x%x to base_param[%s] 0x%x' % (addr, base, self.base_params[base]))
                if addr >= self.base_params[base]:
                    delta = addr - self.base_params[base]
                    #self.lgr.debug('\t\tgetBestBase delta 0x%x, best_base_delta %s' % (delta, str(best_base_delta)))
                    if best_base_delta is None or delta < best_base_delta:
                        best_base_delta = delta
                        best_base = base

            for other in self.other_addrs:
                if addr >= other:
                    delta = addr - other
                    if best_base_delta is None or delta < best_base_delta:
                        #self.lgr.debug('\t\tgetBestBase OTHER delta 0x%x, best_base_delta %s' % (delta, str(best_base_delta)))
                        best_base_delta = delta
                        best_base = other

            if best_base is None:
                best_base = 'unknown'
                best_base_delta = 0
                #self.lgr.error('\t\taddRef best_base is not set?  addr 0x%x ' % (addr))

            #if type(best_base) is int:
            #    self.lgr.debug('\tgetBestBase got 0x%x delta 0x%x' % (best_base, best_base_delta))
            #else:
            #    self.lgr.debug('\tgetBestBase got %s delta 0x%x' % (best_base, best_base_delta))
            return best_base, best_base_delta
 
        def addRef(self, addr, value, hexstring, size, other_ptr):
            ''' Record a reference to user space during a system call '''
            retval = True
            best_base, best_base_delta = self.getBestBase(addr)
            ''' maybe done doing real work?? '''
            #if best_base_delta > 0x1000000:
            #    retval = False
            ref_of_base = None
            if type(best_base) is int:
                ref_of_base = self.other_addrs[best_base]
            if other_ptr is not None:
                other_ref = self.OtherRef(other_ptr, best_base, best_base_delta, ref_of_base, self.lgr)
                #self.lgr.debug('\taddRef append 0x%x to other_ptr ref to string %s' % (other_ptr, other_ref.toString()))
                self.other_addrs[other_ptr] = other_ref
            new_ref = self.ParamRef(addr, 'read', value, hexstring, other_ptr, size, best_base, best_base_delta, ref_of_base)
            self.refs.append(new_ref)

            if self.prev_read_addr is not None and (addr == (self.prev_read_addr-self.mem_utils.WORD_SIZE)):
                self.read_sequence = self.read_sequence + 1
                #if self.read_sequence > 5:
                if self.read_sequence > 5000:
                    retval = False
            else:
                self.read_sequence = 0
            self.read_wrote_addr = addr
            return retval

        def numRefs(self):
            return len(self.refs)
 
        def refOfBase(self, base):
            retval = None
            if type(base) is int:
                retval = self.other_addrs[base]
            return retval

        def mergeRef(self):
            ''' Go through all reference records and merge obvious strings into a single reference '''
            #self.lgr.debug('mergeRef')
            candidate = {}
            current_base = None
            current_base_of_base = None
            current_base_of_base_delta = None
            current_base_delta = None
            current_addr = None
            running_count = 0
            running_size = 0
            running_hexstring = ''
            running_value = None
            index = 0
            running_start = None
            add_these = {}
            rm_these = {}
            for reference in self.refs:
                if current_base is None or reference.best_base != current_base or reference.addr != (current_addr - reference.size):
                    ''' TBD clean up any open runs ''' 
                    if running_count > 3 or len(running_hexstring)>20:
                        #start_addr = current_start - running_size + 1
                        #self.lgr.debug('merge running size 0x%x  current_start 0x%x  yields start addr 0x%x' % (running_size, current_start, start_addr))
                        start_addr = current_addr
                        ref_of_base = self.refOfBase(current_base)
                        new_ref = self.ParamRef(start_addr, current_operator, running_value, running_hexstring, None, running_size, 
                             current_base, current_base_delta, ref_of_base)
                        add_these[running_start] = new_ref
                        rm_these[running_start] = running_count
                    if type(reference.best_base) is str and reference.best_base.startswith('rsp'):
                        index = index + 1 
                        continue

                    current_start = reference.addr
                    current_operator = reference.operator
                    current_base = reference.best_base
                    current_base_delta = reference.best_base_delta
                    current_addr = reference.addr 
                    running_size = reference.size
                    running_count = 0
                    running_hexstring = reference.hexstring
                    running_value = reference.value
                    running_start = index
                  
                else:
                    #self.lgr.debug('mergeRef ref.addr 0x%x  size %d  current_addr 0x%x'  % (reference.addr, reference.size, current_addr))
                    current_addr = reference.addr 
                    running_count = running_count+1
                    running_size = running_size + reference.size
                    running_hexstring = reference.hexstring+running_hexstring
                    running_value = reference.value+running_value
                    current_base_delta = reference.best_base_delta

                index = index + 1
            for rm_index in rm_these:
                end = rm_index + rm_these[rm_index] + 1
                #self.lgr.debug('mergeRef rm %d to %d' % (rm_index, end))
                del self.refs[rm_index:end]
            for add_index in add_these:
                self.refs.insert(add_index, add_these[add_index])

        def addWrote(self, addr, value, hexstring, size):
            retval = True
            best_base, best_base_delta = self.getBestBase(addr)
            ref_of_base = self.refOfBase(best_base)
            new_ref = self.ParamRef(addr, 'wrote', value, hexstring, None, size, best_base, best_base_delta, ref_of_base)
            self.wrote_values[addr] = new_ref
            if self.prev_wrote_addr is not None and (addr == (self.prev_wrote_addr+self.mem_utils.WORD_SIZE)):
                self.wrote_sequence = self.wrote_sequence + 1
                if self.wrote_sequence > 500:
                    retval = False
            else:
                self.wrote_sequence = 0
            self.prev_wrote_addr = addr
            return retval

        def getCallName(self):
            return self.call_name
