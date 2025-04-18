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
    Use simics to disassemble the instruction at a given address.  However if that
    address is not yet mapped, then read the instruction from the binary per the
    SO map.
    Uses the capstone engine.
'''
from simics import *
import sys
import os
sys.path.insert(0,'/usr/local/lib/python3.10/dist-packages')
home=os.getenv('HOME')
if home is not None:
    local_path = home+'/.local/lib/python3.10/site-packages'
    sys.path.insert(0,local_path)
try:
    from capstone import *
except:
    print('WARNING, failed to import capstone*************************')
    pass
class Disassemble():
    def __init__(self, top, cpu, so_map, lgr):
        self.so_map = so_map
        self.cpu = cpu
        self.lgr = lgr
        self.top = top
        self.prog_bytes = {}
        try:
            if cpu.architecture.startswith('arm'):
                self.md32 = Cs(CS_ARCH_ARM, CS_MODE_ARM)
                self.md64 = Cs(CS_ARCH_ARM, CS_MODE_ARM64)
            else:
                self.md32 = Cs(CS_ARCH_X86, CS_MODE_32)
                self.md64 = Cs(CS_ARCH_X86, CS_MODE_64)
            self.lgr.debug('disassemble did capstone init for cpu %s' % cpu.name)
        except:
            self.lgr.error('disassemble failed capstone init for cpu %s' % cpu.name)
            self.md32 = None
            self.md64 = None

    def getPrevInstruction(self, addr, fun_addr):
        ''' Find the instruction that preceeds the given address. Inputs are load values '''
        retval = None
        if self.so_map.wordSize() == 4:
            #self.lgr.debug('disassemble getPrevInstruction word size 4')
            md = self.md32
        else:
            #self.lgr.debug('disassemble getPrevInstruction word size 8')
            md = self.md64
        max_instructs = int((addr - fun_addr) / 2)
        if md is None:
            self.lgr.error('disassemble getPrevInstruction but md is None')
            return None
        fname, load_addr, end = self.getProgBytes(addr)
        if fname is None:
            #self.lgr.debug('disassemble getPrevInstruction not fname for addr 0x%x' % addr)
            return None
        fun_addr_orig = fun_addr - load_addr 
        # for windows
        # 0x400 is the file pointer for the text section.  0x1000 is the address of text.
        if self.top.isWindows():
            fun_addr_orig = fun_addr_orig + 0x400 - 0x1000
        prev = fun_addr
        prev_mnemonic = None
        #self.lgr.debug('disassemble getPrevInstruction for addr 0x%x fun_addr 0x%x adjusted to 0x%x fname %s, load_addr 0x%x' % (addr, 
        #       fun_addr, fun_addr_orig, fname, load_addr))
        for (address, size, mnemonic, op_str) in md.disasm_lite(self.prog_bytes[fname][fun_addr_orig:], fun_addr, count=max_instructs):
            #self.lgr.debug("disassemble getPrevInstruction 0x%x:\t%s\t%s" %(address, mnemonic, op_str))
            if address == addr:
                if prev_mnemonic == 'call':
                    retval = prev 
                else:
                    #self.lgr.debug('disassemble getPrevInstruction reached address 0x%x, but not a call, was %s' % (addr, prev_mnemonic))
                    pass
                break
            prev = address 
            prev_mnemonic = mnemonic 
        #if retval is None:
        #    # could be odd data on stack that would fall in this function
        #    self.lgr.debug('disassemble getPrevInstruction failed to find address 0x%x in function 0x%x after %d instructions' % (addr, fun_addr, max_instructs))
        #else:
        #    self.lgr.debug('disassemble getPrevInstruction prev instruct was at 0x%x' % retval) 
        return retval

    def getProgBytes(self, addr):
        fname, load_addr, end = self.so_map.getSOInfo(addr)
        if fname is not None:
            load_offset = self.so_map.getLoadOffset(fname)
            if fname is not None:
                #self.lgr.debug('disassemble getProgBytes addr 0x%x is fname %s load_addr 0x%x, load_offset 0x%x' % (addr, fname, load_addr, load_offset))
                if fname not in self.prog_bytes:
                    full_path = self.top.getFullPath(fname=fname)
                    with open(full_path, 'rb') as fh:
                       self.prog_bytes[fname] = fh.read()
            else:
                self.lgr.error('disassemble getProgBytes failed to get fname for addr 0x%x is fname %s' % (addr))
        else:
            self.lgr.debug('disassemble getProgBytes got no fname for addr 0x%x' % addr)
        return fname, load_addr, end 

    def getDisassemble(self, addr):
        ''' NOT right for windows '''
        retval = None
        if self.so_map.wordSize() == 4:
            md = self.md32
        else:
            md = self.md64
        instruct = SIM_disassemble_address(self.cpu, addr, 1, 0)
        if md is not None and 'illegal memory mapping' in instruct[1]:
            fname, load_addr, end = self.getProgBytes(addr)
            delta = addr - load_addr
            for (address, size, mnemonic, op_str) in md.disasm_lite(self.prog_bytes[fname][delta:], addr, count=1):
                self.lgr.debug("disassemble getDisassemble 0x%x:\t%s\t%s" %(address, mnemonic, op_str))
                retval = (size, mnemonic+' '+op_str)
        else:
            retval = instruct
        return retval
