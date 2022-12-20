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

import xml.etree.ElementTree as ET
import memUtils
import os
import shutil
import simics
try:
    import ConfigParser
except:
    import configparser as ConfigParser
from simics import *
'''
    Create an xml formatted log of CB system calls.  One file is created for each session, and the
    file name is derived from the replay file (pov or poller).
'''
MAX_CALLS = 5000
def indent(elem, level=0):
    i = "\n" + level*"  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i
 
class callLog():
    def __init__(self, top, os_utils, param, pid, program, replay_file, szk, lgr, logdir, cgc_bytes):
        self.top = top
        self.os_utils = os_utils
        self.pid = pid
        self.cgc_bytes = cgc_bytes
        self.program = program
        self.logdir = logdir
        #self.replay_file = os.path.splitext(os.path.basename(replay_file))[0]
        self.replay_file = replay_file
        self.doc = ET.Element('call_log')
        self.param = param
        self.szk = szk
        self.lgr = lgr
        self.pid = pid
        self.program = program
        self.part = 1
        pid_e = ET.SubElement(self.doc, 'pid')
        pid_e.text = '%s' % pid
        comm_e = ET.SubElement(self.doc, 'comm')
        comm_e.text = program
        part_e = ET.SubElement(self.doc, 'part')
        part_e.text = str(self.part)
        self.fname = None
        self.call_count = 0

    def rotateLog(self):
        self.doneCallLog()
        self.part += 1
        self.doc = ET.Element('call_log')
        pid_e = ET.SubElement(self.doc, 'pid')
        pid_e.text = '%s' % self.pid
        comm_e = ET.SubElement(self.doc, 'comm')
        comm_e.text = self.program
        part_e = ET.SubElement(self.doc, 'part')
        part_e.text = str(self.part)
        self.call_count = 0
         
    def execReturn(self, frame, cpu, prog_sections):
        er = ET.SubElement(self.doc, 'exec_return')
        cycle_e = ET.SubElement(er, 'cycle')
        cycle_e.text = '%x' % SIM_cycle_count(cpu)
        sp = ET.SubElement(er, 'esp')
        sp.text = '%x' % frame['esp']
        ip = ET.SubElement(er, 'eip')
        ip.text = '%x' % frame['eip']
        '''
        try:
            elf_data = int(prog_sections.get("elf", "data"), 16)
            elf_data_size = int(prog_sections.get("elf", "data_size"), 16)
            data = ET.SubElement(er, 'data')
            data.text = '%x' % elf_data
            data_size = ET.SubElement(er, 'data_size')
            data_size.text = '%x' % elf_data_size
        except ConfigParser.NoSectionError:
            print 'NO ELF CONFIG FILE FOR Program'
            pass
        except ConfigParser.NoOptionError:
            pass
        try:
            elf_bss = int(prog_sections.get("elf", "bss"), 16)
            bss = ET.SubElement(er, 'bss')
            bss.text = '%x' % elf_bss
            elf_bss_size = int(prog_sections.get("elf", "bss_size"), 16)
            bss_size = ET.SubElement(er, 'bss_size')
            bss_size.text = '%x' % elf_bss_size
        except ConfigParser.NoOptionError:
            pass
        '''

    def doReceive(self, frame, cpu):
        receive = ET.SubElement(self.doc, 'receive')
        cycle_e = ET.SubElement(receive, 'cycle')
        cycle_e.text = '%x' % SIM_cycle_count(cpu)
        eip_e = ET.SubElement(receive,'eip')
        eip_e.text = '%x' % frame['eip']
        fd_e = ET.SubElement(receive, 'fd')
        fd_e.text = '%d' % frame['ebx']
        buf_e = ET.SubElement(receive, 'buf')
        buf_e.text = '%x' % frame['ecx']
        num_bytes = self.os_utils.sysCallNumBytes(self.param, cpu, self.cgc_bytes)
        num_bytes_e = ET.SubElement(receive, 'num_bytes')
        num_bytes_e.text = '%d' % num_bytes
        count_e = ET.SubElement(receive, 'count')
        count_e.text = '%d' % frame['edx']
        rx_bytes_e = ET.SubElement(receive, 'rx_bytes')
        rx_bytes_e.text = '%x' % frame['esi']
        if num_bytes > 0:
           data_e = ET.SubElement(receive, 'read_data')
           data_e.text = self.top.getBytes(cpu, num_bytes, frame['ecx'])
        if self.call_count > MAX_CALLS:
            self.rotateLog()
        else:
            self.call_count += 1

    def doLinuxRead(self, frame, cpu):
        read = ET.SubElement(self.doc, 'read')
        cycle = SIM_cycle_count(cpu)
        #print 'cycle is %x' % cycle
        cycle_e = ET.SubElement(read, 'cycle')
        cycle_e.text = '%x' % cycle
        eip_e = ET.SubElement(read,'eip')
        eip_e.text = '%x' % frame['eip']
        fd_e = ET.SubElement(read, 'fd')
        fd_e.text = '%d' % frame['ebx']
        buf_e = ET.SubElement(read, 'buf')
        buf_e.text = '%x' % frame['ecx']
        num_bytes = frame['eax']
        num_bytes_e = ET.SubElement(read, 'num_bytes')
        num_bytes_e.text = '%d' % num_bytes
        count_e = ET.SubElement(read, 'count')
        count_e.text = '%d' % frame['edx']
        if num_bytes > 0:
           data_e = ET.SubElement(read, 'read_data')
           data_e.text = self.top.getBytes(cpu, num_bytes, frame['ecx'])
        if self.call_count > MAX_CALLS:
            self.rotateLog()
        else:
            self.call_count += 1

    def doLinuxWrite(self, frame, cpu):
        write = ET.SubElement(self.doc, 'write')
        cycle_e = ET.SubElement(write, 'cycle')
        cycle_e.text = '%x' % SIM_cycle_count(cpu)
        eip_e = ET.SubElement(write,'eip')
        eip_e.text = '%x' % frame['eip']
        fd_e = ET.SubElement(write, 'fd')
        fd_e.text = '%d' % frame['ebx']
        buf_e = ET.SubElement(write, 'buf')
        buf_e.text = '%x' % frame['ecx']
        num_bytes = frame['eax']
        num_bytes_e = ET.SubElement(write, 'num_bytes')
        num_bytes_e.text = '%d' % num_bytes
        count_e = ET.SubElement(write, 'count')
        count_e.text = '%d' % frame['edx']
        if num_bytes > 0:
           data_e = ET.SubElement(write, 'write_data')
           data_e.text = self.top.getBytes(cpu, num_bytes, frame['ecx'])

    ''' TBD '''
    def doLinuxBrk(self, frame, cpu):
        brk = ET.SubElement(self.doc, 'bkr')
        cycle_e = ET.SubElement(brk, 'cycle')
        cycle_e.text = '%x' % SIM_cycle_count(cpu)
        eip_e = ET.SubElement(brk,'eip')
        eip_e.text = '%x' % frame['eip']
        size = ET.SubElement(brk, 'size')
        size.text = '%x' % frame['ebx']
        if self.call_count > MAX_CALLS:
            self.rotateLog()
        else:
            self.call_count += 1

    def doLinuxMmap(self, frame, cpu):
        mmap = ET.SubElement(self.doc, 'mmap')
        cycle_e = ET.SubElement(mmap, 'cycle')
        cycle_e.text = '%x' % SIM_cycle_count(cpu)
        eip_e = ET.SubElement(mmap,'eip')
        eip_e.text = '%x' % frame['eip']
        addr = ET.SubElement(mmap, 'address')
        addr.text = '%x' % frame['eax']
        size = ET.SubElement(mmap, 'size')
        size.text = '%x' % frame['ecx']
        if self.call_count > MAX_CALLS:
            self.rotateLog()
        else:
            self.call_count += 1

    def doLinuxUnMap(self, frame, cpu):
        unmap = ET.SubElement(self.doc, 'munmap')
        cycle_e = ET.SubElement(unmap, 'cycle')
        cycle_e.text = '%x' % SIM_cycle_count(cpu)
        eip_e = ET.SubElement(unmap,'eip')
        eip_e.text = '%x' % frame['eip']
        addr = ET.SubElement(unmap, 'address')
        addr.text = '%x' % frame['ebx']
        size = ET.SubElement(unmap, 'size')
        size.text = '%x' % frame['ecx']
        if self.call_count > MAX_CALLS:
            self.rotateLog()
        else:
            self.call_count += 1

    def doLinuxSocket(self, frame, cpu):
        if frame['ebx'] == 5:
            accept = ET.SubElement(self.doc, 'accept')
            cycle_e = ET.SubElement(accept, 'cycle')
            cycle_e.text = '%x' % SIM_cycle_count(cpu)
            eip_e = ET.SubElement(accept,'eip')
            eip_e.text = '%x' % frame['eip']
        if self.call_count > MAX_CALLS:
            self.rotateLog()
        else:
            self.call_count += 1
            

    def doTransmit(self, frame, cpu):
        transmit = ET.SubElement(self.doc, 'transmit')
        cycle_e = ET.SubElement(transmit, 'cycle')
        cycle_e.text = '%x' % SIM_cycle_count(cpu)
        eip_e = ET.SubElement(transmit,'eip')
        eip_e.text = '%x' % frame['eip']
        fd_e = ET.SubElement(transmit, 'fd')
        fd_e.text = '%d' % frame['ebx']
        buf_e = ET.SubElement(transmit, 'buf')
        buf_e.text = '%x' % frame['ecx']
        num_bytes = self.os_utils.sysCallNumBytes(self.param, cpu, self.cgc_bytes)
        num_bytes_e = ET.SubElement(transmit, 'num_bytes')
        num_bytes_e.text = '%d' % num_bytes
        count_e = ET.SubElement(transmit, 'count')
        count_e.text = '%d' % frame['edx']
        tx_bytes_e = ET.SubElement(transmit, 'tx_bytes')
        tx_bytes_e.text = '%x' % frame['esi']
        if num_bytes > 0:
           data_e = ET.SubElement(transmit, 'write_data')
           data_e.text = self.top.getBytes(cpu, num_bytes, frame['ecx'])
        if self.call_count > MAX_CALLS:
            self.rotateLog()
        else:
            self.call_count += 1

    def doRandom(self, frame, cpu):
        random = ET.SubElement(self.doc, 'random')
        cycle_e = ET.SubElement(random, 'cycle')
        cycle_e.text = '%x' % SIM_cycle_count(cpu)
        eip_e = ET.SubElement(random,'eip')
        eip_e.text = '%x' % frame['eip']
        buf_e = ET.SubElement(random, 'buf')
        buf_e.text = '%x' % frame['ebx']
        num_bytes = self.os_utils.sysCallNumBytes(self.param, cpu, self.cgc_bytes)
        num_bytes_e = ET.SubElement(random, 'num_bytes')
        num_bytes_e.text = '%d' % num_bytes
        count_e = ET.SubElement(random, 'count')
        count_e.text = '%d' % frame['ecx']
        rnd_bytes_e = ET.SubElement(random, 'rnd_bytes')
        rnd_bytes_e.text = '%x' % frame['esi']
        if num_bytes > 0:
           buf_e = ET.SubElement(random, 'write_data')
           buf_e.text = self.top.getBytes(cpu, num_bytes, frame['ebx'])
        if self.call_count > MAX_CALLS:
            self.rotateLog()
        else:
            self.call_count += 1

    def doFdWait(self, frame, cpu, fd_set_size):
        fdwait = ET.SubElement(self.doc, 'fdwait')
        cycle_e = ET.SubElement(fdwait, 'cycle')
        cycle_e.text = '%x' % SIM_cycle_count(cpu)
        eip_e = ET.SubElement(fdwait,'eip')
        eip_e.text = '%x' % frame['eip']
        nfds_e = ET.SubElement(fdwait, 'nfds')
        nfds_e.text = '%d' % frame['ebx']

        fd_set_e = ET.SubElement(fdwait, 'fd_set')
        fd_set_ptr = frame['ecx']
        fd_set_e.text = '%x' % fd_set_ptr
        
        fd_set_data_e = ET.SubElement(fdwait, 'fd_set_data')
        fd_set_data_e.text = self.top.getBytes(cpu, fd_set_size, fd_set_ptr)

        timeval_ptr_e = ET.SubElement(fdwait, 'timeout')
        timeval_ptr = frame['edx']
        timeval_ptr_e.text = '%x' % timeval_ptr
        if timeval_ptr != 0:
            timeout_data_e = ET.SubElement(fdwait, 'timeout_data')
            timeout_data_sec = ET.SubElement(timeout_data_e, 'sec')
            timeout_data_sec.text = '%d' % memUtils.readWord(cpu, timeval_ptr)
            timeout_data_usec = ET.SubElement(timeout_data_e, 'usec')
            timeval_data_usec = memUtils.readWord(cpu, timeval_ptr+memUtils.WORD_SIZE)
        readyfds_e = ET.SubElement(fdwait, 'readyfds')
        readyfds_ptr = frame['esi']
        readyfds_e.text = '%x' % readyfds_ptr
        if readyfds_ptr != 0:
            readyfds_data = ET.SubElement(fdwait, 'readyfds_data')
            read_value = memUtils.readWord(cpu, readyfds_ptr)
            readyfds_data.text = '%x' % read_value
        if self.call_count > MAX_CALLS:
            self.rotateLog()
        else:
            self.call_count += 1

    def doAllocate(self, frame, cpu):
        allocate = ET.SubElement(self.doc, 'allocate')
        cycle_e = ET.SubElement(allocate, 'cycle')
        cycle_e.text = '%x' % SIM_cycle_count(cpu)
        eip_e = ET.SubElement(allocate,'eip')
        eip_e.text = '%x' % frame['eip']
        length = ET.SubElement(allocate, 'length')
        length.text = '%d' % frame['ebx']
        is_X = ET.SubElement(allocate, 'is_X')
        is_X.text = '%d' % frame['ecx']
        addr = ET.SubElement(allocate, 'addr')
        addr.text = '%x' % frame['edx']
        addr_data = ET.SubElement(allocate, 'addr_data')
        addr_data.text = '%x' % memUtils.readPtr(cpu, frame['edx'])
        if self.call_count > MAX_CALLS:
            self.rotateLog()
        else:
            self.call_count += 1

    def doDeallocate(self, frame, cpu):
        deallocate = ET.SubElement(self.doc, 'deallocate')
        cycle_e = ET.SubElement(deallocate, 'cycle')
        cycle_e.text = '%x' % SIM_cycle_count(cpu)
        eip_e = ET.SubElement(deallocate,'eip')
        eip_e.text = '%x' % frame['eip']
        address = ET.SubElement(deallocate, 'addr')
        address.text = '%x' % frame['ebx']
        length = ET.SubElement(deallocate, 'length')
        length.text = '%d' % frame['ecx']
        if self.call_count > MAX_CALLS:
            self.rotateLog()
        else:
            self.call_count += 1

    def doneCallLog(self):
        indent(self.doc)
        tree = ET.ElementTree(self.doc)
        
        if self.fname is None:
            log_path = self.logdir+'/call_logs/'+self.program
            try:
                os.makedirs(log_path)
            except:
                pass
            i = 0
            while self.fname is None and i <= 999:
                tmp_name = log_path+'/%s_%03d' % (self.replay_file, i)
                full_name = tmp_name+'-%04d.xml' % (self.part)
                if not os.path.isfile(full_name):
                    self.fname = tmp_name
                i += 1
        if self.fname is None:
            print('clean up your call_log directory!')
            exit(1)
        full_name = self.fname+'-%04d.xml' % (self.part)
        try:
            tree.write(full_name)
            self.lgr.debug('wrote call log to '+full_name)
        except:
            dump = ET.tostring(tree.getroot())
            self.lgr.critical("doneCallLog ERROR file is %s, log content follows\n%s" % (full_name, dump))
            exit(1)
        del self.doc
        # TBD must use SCP -- also, add configuration value to supress this
        '''
        if self.replay_file is not None: 
            replay_dir = self.szk.replayPathFromName(self.replay_file)
            if replay_dir is not None:
                parent = os.path.dirname(replay_dir)
                dest = parent+'/callLog.xml'
                shutil.copyfile(fname, dest)
                self.lgr.debug('callLog copied syscall log from %s to %s' % (fname, dest))
        '''
