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
class FunMgr():
    def __init__(self, top, cpu, mem_utils, ida_funs, relocate_funs, lgr):
        self.relocate_funs = relocate_funs
        self.ida_funs = ida_funs
        self.cpu = cpu
        self.top = top
        self.lgr = lgr
        if cpu.architecture == 'arm':
            self.callmn = 'bl'
            self.jmpmn = 'bx'
        else:
            self.callmn = 'call'
            self.jmpmn = 'jmp'

    def isCall(self, instruct):
        if instruct.startswith(self.callmn):
            return True
        else:
            return False

    def funFromAddr(self, addr):
        fun = None
        if addr in self.relocate_funs:
            fun = self.relocate_funs[addr]
        elif self.ida_funs is not None:
            #self.lgr.debug('stackTrace funFromAddr 0x%x not in relocate' % addr)
            fun = self.ida_funs.getName(addr)
        return fun

    def getFunName(self, instruct):
        ''' get the called function address and its name, if known '''
        if self.cpu.architecture != 'arm' and instruct.startswith('jmp dword'):
            parts = instruct.split()
            addrbrack = parts[3].strip()
            addr = None
            try:
                addr = int(addrbrack[1:-1], 16)
            except:
                #self.lgr.error('stackTrace expected jmp address %s' % instruct)
                return None, None
            fun = str(self.funFromAddr(addr))
            if fun is None:
                call_addr = self.mem_utils.readPtr(self.cpu, addr)
                fun = str(self.funFromAddr(call_addr))
            else:
                call_addr = addr
            #self.lgr.debug('getFunName addr 0x%x, call_addr 0x%x got %s' % (addr, call_addr, fun))
 
        else:
            parts = instruct.split()
            if len(parts) != 2:
                #self.lgr.debug('stackTrace getFunName not a call? %s' % instruct)
                return None, None
            fun = None
            call_addr = None
            try:
                call_addr = int(parts[1],16)
                fun = str(self.funFromAddr(call_addr))
                #self.lgr.debug('getFunName call_addr 0x%x got %s' % (call_addr, fun))
            except ValueError:
                #self.lgr.debug('getFunName, %s not a hex' % parts[1])
                pass
        return call_addr, fun
