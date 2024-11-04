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
sys.path.insert(0,'/usr/local/lib/python3.10/dist-packages')
try:
    from capstone import *
except:
    pass
class Disassemble():
    def __init__(self, top, cpu, so_map, lgr):
        self.so_map = so_map
        self.cpu = cpu
        self.lgr = lgr
        self.top = top
        self.prog_bytes = {}
        try:
            if cpu.architecture == 'arm':
                self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            elif cpu.architecture == 'arm64':
                self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM64)
            else:
                self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        except:
            self.md = None

    def getDisassemble(self, addr):
        retval = None
        instruct = SIM_disassemble_address(self.cpu, addr, 1, 0)
        if self.md is not None and 'illegal memory mapping' in instruct[1]:
            fname, load_addr, end = self.so_map.getSOInfo(addr)
            self.lgr.debug('disassemble getDisassemble addr 0x%x is fname %s' % (addr, fname))
            if fname not in self.prog_bytes:
                full_path = self.top.getFullPath(fname=fname)
                with open(full_path, 'rb') as fh:
                   self.prog_bytes[fname] = fh.read()
            delta = addr - load_addr
            for (address, size, mnemonic, op_str) in self.md.disasm_lite(self.prog_bytes[fname][delta:], addr, count=1):
                self.lgr.debug("disassemble getDisassemble 0x%x:\t%s\t%s" %(address, mnemonic, op_str))
                retval = (size, mnemonic+' '+op_str)
        else:
            retval = instruct
        return retval
