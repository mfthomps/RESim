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
import idaFuns
import userIterators
import elfText
import resimUtils
import winProg
import os
import json
class FunMgr():
    def __init__(self, top, cpu, mem_utils, lgr):
        self.relocate_funs = {}
        self.ida_funs = None
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.top = top
        self.lgr = lgr
        self.so_checked = []
        if cpu.architecture == 'arm':
            self.callmn = 'bl'
            self.jmpmn = 'bx'
        else:
            self.callmn = 'call'
            self.jmpmn = 'jmp'

    def getFun(self, addr):
        return self.ida_funs.getFun(addr)

    def getName(self, addr):
        return self.ida_funs.getName(addr)

    def demangle(self, fun):
        return self.ida_funs.demangle(fun)

    def isFun(self, fun):
        ''' given fun value may reflect random load base address '''
        retval = False
        if self.ida_funs.isFun(fun):
            retval = True
        elif fun in self.relocate_funs:
            retval = True
        return retval
 
    ''' TBD extend linux soMap to pass load addr '''
    def add(self, path, start, offset=0, text_offset=0):
        #self.lgr.debug('funMgr add path %s' % path)
        if self.ida_funs is not None:
            use_offset = start
            if offset != 0:
                use_offset = offset - text_offset
            self.ida_funs.add(path, use_offset)
            if offset is not None:
                self.lgr.debug('funMgr add call setRelocate funs path %s offset 0x%x   start 0x%x ' % (path, use_offset, start))
            else:
                self.lgr.debug('funMgr add call setRelocate funs path %s  start 0x%x offset was None' % (path, start))
            
           
            self.setRelocateFuns(path, offset=use_offset)
        else:
            self.lgr.debug('funMgr add called with no IDA funs defined')
            

    def isCall(self, instruct):
        if instruct.startswith(self.callmn):
            return True
        else:
            return False

    def inFun(self, prev_ip, call_to):
        return self.ida_funs.inFun(prev_ip, call_to)

    def funFromAddr(self, addr):
        fun = None
        if addr in self.relocate_funs:
            #self.lgr.debug('funMgr funFromAddr 0x%x in relocate' % addr)
            fun = self.relocate_funs[addr]
        elif self.ida_funs is not None:
            #self.lgr.debug('funMgr funFromAddr 0x%x not in relocate' % addr)
            fun = self.ida_funs.getFunName(addr)
        return fun

    def getFunName(self, addr):
        return self.ida_funs.getFunName(addr)

    def isIterator(self, addr):
        if self.user_iterators is not None:
            return self.user_iterators.isIterator(addr)

    def setUserIterators(self, iterators):
        self.user_iterators = iterators

    def addIterator(self, fun):
        if self.user_iterators is not None:
            self.user_iterators.add(fun)

    def hasIDAFuns(self):
        if self.ida_funs is not None:
            return True
        else:
            return False

    def getIDAFunsOld(self, full_path, root_prefix):
        full_path = resimUtils.realPath(full_path)
        fun_path = full_path+'.funs'
        iterator_path = full_path+'.iterators'
        root_dir = os.path.basename(root_prefix)
        self.user_iterators = userIterators.UserIterators(iterator_path, self.lgr, root_dir)
        if not os.path.isfile(fun_path):
            ''' TBD REMOVE THIS...        No functions file, check for symbolic links '''
            if os.path.islink(full_path):
                parent = os.path.dirname(full_path)
                actual = os.readlink(full_path)
                actual = os.path.join(parent, actual)
                self.lgr.debug('getIDAFuns is link, actual %s' % actual)
                fun_path = actual+'.funs'

        if os.path.isfile(fun_path):
            if self.top.isWindows():
                self.ida_funs = idaFuns.IDAFuns(fun_path, self.lgr)
            else: 
                self.ida_funs = idaFuns.IDAFuns(fun_path, self.lgr)
            self.lgr.debug('getIDAFuns using IDA function analysis from %s' % fun_path)
        else:
            self.lgr.warning('No IDA function file at %s' % fun_path)

    def getIDAFuns(self, full_path, root_prefix, offset):
        if not self.top.isWindows():
            ''' much of the link mess is due to linux target file systems with links.  Also using links while
                figuring out the windows directory structures. '''
            full_path = resimUtils.realPath(full_path)
        #self.lgr.debug('getIDAFuns full_path %s  root_prefix %s' % (full_path, root_prefix))
        if full_path.startswith(root_prefix):
            analysis_path = self.top.getAnalysisPath(full_path)
            #self.lgr.debug('getIDAFuns analysis_path %s' % analysis_path) 

            fun_path = analysis_path+'.funs'
            iterator_path = analysis_path+'.iterators'
            root_dir = os.path.basename(root_prefix)
            self.user_iterators = userIterators.UserIterators(iterator_path, self.lgr, root_dir)
            
            if os.path.isfile(fun_path):
                self.ida_funs = idaFuns.IDAFuns(fun_path, self.lgr, offset=offset)
                self.setRelocateFuns(analysis_path, offset=offset)
                self.lgr.debug('getIDAFuns using IDA function analysis from %s' % fun_path)
            else:
                self.lgr.debug('getIDAFuns No IDA function file at %s try using old paths ' % fun_path)
                self.getIDAFunsOld(full_path, root_prefix)
                self.setRelocateFuns(full_path)

        else:
            self.lgr.error('getIDAFuns full path %s does not start with prefix %s' % (full_path, root_prefix))

    def setRelocateFuns(self, full_path, offset=0):
        #self.lgr.debug('funMgr setRelocateFuns %s offset is 0x%x' % (full_path, offset))
        if full_path.endswith('.funs'):
            full_path = full_path[:-5]
        relocate_path = full_path+'.imports'
        if os.path.isfile(relocate_path):
            with open(relocate_path) as fh:
                funs = json.load(fh)
                for addr_s in funs:
                    demang = self.demangle(funs[addr_s])
                    if demang is not None:
                        rel_fun_name = demang
                    else:
                        rel_fun_name = funs[addr_s]
                    rel_fun_name = idaFuns.rmPrefix(rel_fun_name)

                    addr = int(addr_s)
                    adjust = addr+offset
                    #if 'FNET' in relocate_path:
                    #    self.lgr.debug('funMgr setRelocateFuns addr 0x%x offset 0x%x adjusted [0x%x] to %s' % (addr, offset, adjust, funs[addr_s]))
                    if adjust in self.relocate_funs:
                        #self.lgr.debug('funMgr 0x%x already in relocate as %s' % (adjust, self.relocate_funs[adjust]))
                        pass
                    else:
                        self.relocate_funs[adjust] = rel_fun_name
                        #self.lgr.debug('relocate: %s' % rel_fun_name)
                self.lgr.debug('funMgr setRelocateFuns loaded %s relocates for path %s num relocates now %s' % (len(funs), relocate_path, len(self.relocate_funs))) 
        elif False and not self.top.isWindows():
            #TBD Fix this
            prog_path = self.top.getFullPath()
            ''' TBD need to adjust per offset?'''
            new_relocate_funs = elfText.getRelocate(prog_path, self.lgr, self.ida_funs)
            if new_relocate_funs is not None:
                for fun in new_relocate_funs:
                    self.relocate_funs[fun] = new_relocate_funs[fun]
                self.lgr.warning('funMgr setRelocateFuns no file at %s, revert to elf parse got %d new relocate funs' % (relocate_path, len(new_relocate_funs)))
          

    def getFunNameFromInstruction(self, instruct, eip):
        ''' get the called function address and its name, if known '''
        # TBD duplicates much of resolveCall.  merge?
        #self.lgr.debug('funMgr getFunNameFromInstruct insturct: %s' % instruct[1])
        if self.cpu.architecture != 'arm' and instruct[1].startswith('jmp dword'):
            parts = instruct[1].split()
            addrbrack = parts[3].strip()
            addr = None
            try:
                addr = int(addrbrack[1:-1], 16)
            except:
                self.lgr.error('funMgr expected jmp address %s' % instruct[1])
                return None, None
            fun = self.funFromAddr(addr)
            if fun is None:
                call_addr = self.mem_utils.readAppPtr(self.cpu, addr)
                fun = str(self.funFromAddr(call_addr))
                #self.lgr.debug('funMgr fun from addr 0x%x was None used readAddPtr to get call_addr 0x%x' % (addr, call_addr))
            else:
                #self.lgr.debug('funMgr got fun %s from addr 0x%x' % (fun, addr))
                call_addr = addr
            #self.lgr.debug('getFunName addr 0x%x, call_addr 0x%x got %s' % (addr, call_addr, fun))
 
        else:
            parts = instruct[1].split()
            call_addr = None
            fun = None
            #self.lgr.debug('funMgr getFunNameFromInstruction for %s' % instruct[1])
            if parts[-1].strip().endswith(']'):
                #self.lgr.debug('funMgr getFunNameFromInstruction is bracket %s' % instruct[1])
                call_addr, fun = self.indirectCall(instruct, eip)
          
            elif len(parts) == 2:
                try:
                    call_addr = int(parts[1],16)
                except ValueError:
                    #self.lgr.debug('getFunName, %s not a hex' % parts[1])
                    pass
                if call_addr is not None:
                    fun = str(self.funFromAddr(call_addr))
                    #self.lgr.debug('funMgr getFunNameFromInstruction call_addr 0x%x got %s' % (call_addr, fun))
        if fun is not None and (fun.startswith('.') or fun.startswith('_')):
            fun = fun[1:]
        #if call_addr is not None:
        #    self.lgr.debug('funMgr getFunNameFromInstruction returning 0x%x %s' % (call_addr, fun))
        return call_addr, fun

    def resolveCall(self, instruct, eip):      
        ''' given a call 0xdeadbeef, convert the instruction to use the function name if we can find it'''
        retval = instruct[1]
        fun_name = None
        #self.lgr.debug('funMgr resolveCall %s' % instruct[1])
        if instruct[1].startswith(self.callmn):
            faddr = None
            parts = instruct[1].split()
            if parts[-1].strip().endswith(']'):
                faddr, fun_name = self.indirectCall(instruct, eip)
            else:
                try:
                    faddr = int(parts[1], 16)
                    #print('faddr 0x%x' % faddr)
                except ValueError:
                    pass
                if faddr is not None:
                    fun_name = self.funFromAddr(faddr)
            if fun_name is not None:
                if fun_name.startswith('.') or fun_name.startswith('_'):
                    fun_name = fun_name[1:]
                retval = '%s %s' % (self.callmn, fun_name)
                #self.lgr.debug('resolveCall got %s' % retval)
        return retval
   
    def isRelocate(self, addr):
        return addr in self.relocate_funs

    def showRelocate(self, search=None):
        for fun in sorted(self.relocate_funs):
            if search is None or search in self.relocate_funs[fun]:
                print('0x%x %s' % (fun, self.relocate_funs[fun]))

    def showFuns(self, search = False):
        self.ida_funs.showFuns(search=search)

    def showMangle(self, search = False):
        self.ida_funs.showMangle(search=search)

    def indirectCall(self, instruct, eip):
            retval = None
            fun_name = None
            parts = instruct[1].split()
            if parts[-1].strip().endswith(']'):
                s = parts[-1]
                content = s.split('[', 1)[1].split(']')[0]
                #self.lgr.debug('funMgr indirectCall content <%s> eip: 0x%x' % (content, eip))
                if content.startswith('rip+'):
                    offset_s = content[4:]
                    offset = None
                    try:
                        offset = int(offset_s, 16)
                    except:
                        self.lgr.error('funMgr indirectCall did not get offset from %s' % instruct)
                        return None
                    ''' offset is from IP value following execution of instruction '''
                    retval = eip + offset + instruct[0]
                    fun_name = self.funFromAddr(retval)
                else:
                    addr = None
                    try:
                        addr = int(content, 16)
                    except:
                        pass
                    if addr is not None:
                        #self.lgr.debug('funMgr indirectCall got addr 0x%x' % addr)
                        fun_name = self.funFromAddr(addr)
                        if fun_name is None:
                            retval = self.mem_utils.readAppPtr(self.cpu, addr)
                            if retval is not None:
                                #self.lgr.debug('funMgr indirectCall got 0x%x when reading addr' % retval)
                                fun_name = self.funFromAddr(retval)
                                #self.lgr.debug('funMgr indirectCall got fun %s' % fun_name)
                        else: 
                            retval = addr
            #if retval is not None:
            #    self.lgr.debug('funMgr indirectCall returning 0x%x' % retval)
            return retval, fun_name


    def soChecked(self, addr):
        if addr in self.so_checked:
            return True
        else:
            return False

    def soCheckAdd(self, addr):
        if addr not in self.so_checked: 
            self.so_checked.append(addr)

    def showFunAddrs(self, fun_name):
        ''' given a function name, return its entry points? '''
        for fun in self.relocate_funs:
            if self.relocate_funs[fun] == fun_name:
                print('relocate 0x%x' % fun)
        self.ida_funs.showFunEntries(fun_name)

    def getFunEntry(self, fun_name):
        return self.ida_funs.getFunEntry(fun_name)
