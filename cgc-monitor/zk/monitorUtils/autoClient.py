#!/usr/bin/env python
import sys
import os
import errno
import time
import shutil
from monitorLibs import traceCycles
from monitorLibs import analysisEvents
from monitorLibs import configMgr
from monitorLibs import utils
ia32_regs = ["eax", "ebx", "ecx", "edx", "ebp", "edi", "esi", "eip", "esp"]

def getTagValue(line, find_tag):
    parts = line.split()
    for part in parts:
        if ':' in part:
            tag, value = part.split(':',1)
            if tag.strip() == find_tag:
                return value
    return None

def isReg(reg):
    if reg in ia32_regs:
        return True
    if (len(reg) == 3 and reg.endswith('x')) or (len(reg) == 2 and reg[0] != '0'):
        try:
            dum = int(reg)
            return False
        except:
            pass
        return True
    else:
        return False


def isProtected(s):
    if s.startswith('4347c') or s.startswith('0x4347c'):
        return True
    else:
        return False

class autoClient():
    did_rop = False
    did_nox = False
    def __init__(self, server_in, server_out, lgr):
        self.server_in = server_in
        self.server_out = server_out
        self.lgr = lgr
        self.marks = []
        self.throw_id = None
        self.trace_cycles = None
        self.analysis_events = None
        self.did_rop = False
        self.did_nox = False
        ''' flags rcb behavior that mimics rop, don't follow rop tracks once set '''
        self.bad_rop = False
        self.bad_nox = False

        ''' !!!! copy any other global init to end of waitForReady '''
           
    def getStartCycle(self):
        cmd = '@cgc.getDebugFirstCycle()\n' 
        self.server_in.write(cmd)
        self.server_in.flush()
        sys.stderr.write('getStartCycle wrote command\n')
        while True:
            line = self.server_out.readline()
            if len(line) == 0:
                return None

            print('getStartCycle for got %s' % (line))
            self.lgr.debug('getStartCycle for got %s' % (line))
            if 'start_cycle:' in line:
                return getTagValue(line, 'start_cycle')

    def waitForReady(self):
        retval = True
        self.bad_rop = False
        self.bad_nox = False
        ''' wait for the cgcMonitor indicates a program has reached a debug event '''
        line='  '
        while 'AutoAnalysis ready' not in line.strip() and len(line)>0:
            line = self.server_out.readline()
            sys.stderr.write('waitReady got <%s>\n' % line.strip())
            if 'AutoAnalysis No Event' in line:
                retval = False
                break
            #if 'deleted our_status' in line:
            #    retval = False
            #    break
        if 'throw_id:' in line:
            self.throw_id = getTagValue(line, 'throw_id')
            trace_file = os.path.join('/tmp', self.throw_id+'-trace.log')
            self.trace_cycles = traceCycles.traceCycles(trace_file)
            start_cycle = self.getStartCycle()
            self.lgr.debug('AutoAnalysis is ready for %s, start cycle %s' % (self.throw_id, start_cycle))
            cycle = None
            try:
                cycle = int(start_cycle, 16)
            except:
                print('could not get start cycle from %s' % start_cycle)
                self.lgr.error('could not get start cycle from %s' % start_cycle)
                exit(1)
            self.trace_cycles.setMonitorCycle(cycle)
            self.analysis_events = analysisEvents.analysisEvents(self.throw_id, self.trace_cycles)
        self.marks = self.getMarks()
        rop_count = 0
        for mark in self.marks:
            self.lgr.debug('init mark: %s' % mark)
            if 'rop:' in mark:
                rop_count += 1
        if rop_count > 10:
            ''' assume rcb logic mimicks rop '''
            last_rop = self.getLastROP()
            self.bad_rop = True 
            self.lgr.debug('init rop count > 10, assume it is just the rcb last_rop is %s' % last_rop)
            ''' maybe there is a pearl with the swine? '''
            nox = self.getFirstNOX()
            if nox is not None: 
                address = getTagValue(nox, 'nox')
                address = address[:len(address)-2]
                self.lgr.debug('init, bad_rop processing found nox of %s, nox address is %s, last rop %s' % (nox, address, last_rop))
                if last_rop is not None:
                    last_rop_address = getTagValue(last_rop, 'rop')
                    if last_rop_address.startswith(address):
                        self.lgr.debug('keeping last rop, it starts with address %s' % address)
                        self.bad_rop = False 
                        ''' have a rop leading close to the nox address, likely the same. 
                            remove other rops as not helpful '''
                        copy_mark = list(self.marks)
                        for mark in copy_mark:
                            hack_str = 'rop:%s' % address
                            if 'rop' in mark and not mark.startswith(hack_str):
                                self.marks.remove(mark)

        self.did_rop = False
        self.did_nox = False
        return retval
   
    def getMarks(self):
        retval=[]
        sys.stderr.write('in getMarks\n')
        self.lgr.debug('in getMarks\n')
        self.server_in.write('@cgc.listBookmarks()\n')
        self.server_in.flush()
        sys.stderr.write('getMarks wrote command\n')
        got_start = False
        while True:
            line = self.server_out.readline()
            ''' hack to ignore leftover server fu '''
            if not got_start and '_start+1' not in line:
                continue
            got_start = True
            if line.strip() == '<end of bookmarks>' or len(line)==0:
                self.lgr.debug('end of marks, or empty line %s' % line.strip())
                return retval
            elif ':' in line:
                #print('getMarks got line <%s>' % line.strip())
                mark = line.split(':', 1)[1].strip()
                retval.append(mark)
            else: 
                #print('getMarks unexpected <%s>' % line.strip())
                pass 
    
        print('getMarks done')
        self.lgr.debug('getMarks done')
        return retval
      
    def waitUntilMailbox(self):
        done=False
        while not done:
            line = self.server_out.readline()
            if len(line) == 0 or 'gdbMailbox:' in line:
                print('waitUntilMailbox got line %s' % line.strip())
                self.lgr.debug('waitUntilMailbox got line %s' % line.strip())
                return
            else:
                #print('waitUntilMailbox got line %s' % line.strip())
                pass

    def getFirstROP(self):
        if self.bad_rop:
            return None
        for mark in self.marks:
            if 'rop' in mark:
                return mark
        return None

    def getLastROP(self):
        if self.bad_rop:
            return None
        for mark in reversed(self.marks):
            if 'rop' in mark:
                return mark
        return None

    def getLastProtectedTransmit(self):
        for mark in reversed(self.marks):
            if 'CB transmit protected' in mark:
                return mark
        return None

    def getFirstNOX(self):
        if self.bad_nox:
            return None
        for mark in self.marks:
            if 'nox' in mark:
                return mark
        return None

    def getLastProtected(self):
        for mark in reversed(self.marks):
            if 'protected_memory:' in mark:
                return mark
        return None

    def getPOV(self):
        retval = None
        for mark in self.marks:
            if 'POV' in mark:
                return mark
            elif 'Signal 11' in mark:
                return mark
        return retval

    def getSEGV(self):
        ''' look for segv after type 2 '''
        retval = None
        for mark in marks:
            if 'SEGV' in mark:
                return mark
        return None

    def getRegValue(self, reg):
      ''' returns a string representation of a register value '''
      cmd='@cgc.debugGetReg("%s")\n' % reg
      self.server_in.write(cmd)
      self.server_in.flush()
      while True:
        line = self.server_out.readline()
        if len(line) == 0:
            break
        print('getRegValue for %s got %s' % (reg, line))
        self.lgr.debug('getRegValue for %s got %s' % (reg, line))
        if reg+':' in line:
            return getTagValue(line, reg)
        time.sleep(1)

    def getRegIndirect(self, s):
        if ',' in s:
            op2 = s.split(',')[1]
            if op2.count('[') == 1:
                content = s.split('[', 1)[1].split(']')[0]
                if isReg(content):
                    return content
                else:
                    if content.count('+') == 1:
                        reg1, reg2 = content.split('+')
                        self.lgr.debug('may be a degenerate summing of %s %s' % (reg1, reg2))
                        if isReg(reg1) and isReg(reg2):
                            reg1_value = int(self.getRegValue(reg1), 16) 
                            reg2_value = int(self.getRegValue(reg2), 16) 
                            self.lgr.debug('reg1 0x%x reg2 0x%x' % (reg1_value, reg2_value))
                            if reg1_value < 10:
                                return reg2
                            if reg2_value < 10:
                                return reg1
        return None

    def getRecordReset(self):
        while True:
            line = self.server_out.readline()
            if len(line) == 0:
                break
            print('getRecordReset got %s' % (line))
        
    def idaDone(self):
        cmd='@cgc.idaDone()\n' 
        server_in.write(cmd)
        server_in.flush()
        cmd='continue\n'
        server_in.write(cmd)
        server_in.flush()

    def getDebugReplay(self):
        cmd='@cgc.getDebugReplay()\n' 
        server_in.write(cmd)
        server_in.flush()
        while True:
            line = self.server_out.readline()
            if len(line)==0:
                break
            print('getDebugReplay for got %s' % (line))
            self.lgr.debug('getDebugReplay for got %s' % (line))
            if ' vs ' in line:
                return line.strip()
        

    def goToBookmark(self, mark): 
        cmd='@cgc.goToDebugBookmark("%s")\n' % mark 
        print('goToBookmark %s' % cmd)
        self.lgr.debug('goToBookmark %s' % cmd)
        server_in.write(cmd)
        server_in.flush()
        self.waitUntilMailbox()
        print('goToBookmark done')

    def getInstruct(self):
        retval = None
        address = None
        cmd='disassemble\n'
        server_in.write(cmd)
        server_in.flush()
        while True:
            line = server_out.readline()
            if len(line) == 0:
                print('getInstruct, got zero length line')
                self.lgr.debug('getInstruct, got zero length line')
                break
            print('getInstruct got response %s' % line)
            self.lgr.debug('getInstruct got response %s' % line)
            if 'cs:' in line:
                junk = line.split('cs:')[1]
                address, dumb, retval = junk.split(' ', 2)
                value = int(address,16)
                address = '0x%x' % value
                return address, retval.strip()
        return address, retval
   
    def getLineNumber(self, bm):
        cycle = getTagValue(bm, 'cycle') 
        line_number = self.trace_cycles.getLineNumber(cycle)
        return line_number 

    def taintCall(self, reg, address, instruct, line_number, fh):
        value = self.getRegValue(reg)
        fh.write('Execution path corruption in %s at %s, call to reg %s <%s> instruction #%d\n' % (instruct, address, reg, value, line_number))
        self.lgr.debug('Execution path corruption in %s at %s, call to reg %s <%s> instruction #%d\n' % (instruct, address, reg, value, line_number))
        self.analysis_events.addControlCorruptCall(address, instruct, value, line_number)
        marks = self.getMarks()
        prev_marks = len(marks)
        ''' back track this register value '''
        cmd = '@cgc.revTaintReg("%s")\n' % reg
        self.server_in.write(cmd)
        self.server_in.flush()
        self.waitUntilMailbox()
        marks = self.getMarks()
        if len(marks) > prev_marks:
             fh.write('Reverse data tracking of content of %s:\n' % reg)
             self.analysis_events.addTrack(marks[prev_marks:])
             for mark in marks[prev_marks:]:
                 line_number = self.getLineNumber(mark)
                 fh.write('\t%s instruction#%d\n' % (mark, line_number))

    def lookForCall(self, nox, fh):
        ''' go to the given bookmark, and back up one, if it is a "call", see where its reg value came from '''
        ac.goToBookmark(nox)
        cmd='@cgc.reverseToCallInstruction(True)\n'
        self.server_in.write(cmd)
        self.server_in.flush()
        print('cmd was %s' % cmd)
        self.lgr.debug('cmd was %s' % cmd)
        self.lgr.debug('cmd was %s' % cmd)
        self.waitUntilMailbox()
        address, instruct = self.getInstruct()
        line_number = self.getLineNumber(nox)
        eip = self.getRegValue('eip')
        print('lookForCall after mbox, address %s, instruct %s  eip was %s' % (address, instruct, eip)) 
        self.lgr.debug('lookForCall after mbox, address %s, instruct %s  eip was %s' % (address, instruct, eip)) 
        if instruct.startswith('call'):
            reg = instruct.split(' ')[1]
            if reg in ia32_regs:
                line_number -= 1
                self.taintCall(reg, address, instruct, line_number, fh)
                
    def taintAddr(self, address, fh):
         ''' reverse track content of given address.  return False if it looks like faux rop '''
         retval = True
         prev_marks = len(self.getMarks())
         cmd='@cgc.revTaintAddr(%s)\n' % address
         print('do command %s,  prev_marks was %d' % (cmd, prev_marks))
         self.lgr.debug('do command %s,  prev_marks was %d' % (cmd, prev_marks))
         self.server_in.write(cmd) 
         self.server_in.flush()
         self.waitUntilMailbox()
         marks = self.getMarks()
         #print('new marks length is %d' % len(marks))
         if len(marks) > prev_marks:
             fh.write('Reverse data tracking of content of %s:\n' % address)
             self.lgr.debug('Reverse data tracking of content of %s:\n' % address)
             #print('marks[prev_marks] is %s' % marks[prev_marks]) 
             last_mark = None
             for mark in marks[prev_marks:]:
                 #print('taintAddr, %d get line number for %s' % (i,mark))
                 line_number = self.getLineNumber(mark)
                 fh.write('\t%s instruction#%d\n' % (mark, line_number))
                 self.lgr.debug('\t%s instruction#%d\n' % (mark, line_number))
                 last_mark = mark
             last_instruct = getTagValue(last_mark, 'inst')
             if last_instruct is not None and last_instruct.startswith('call') and (len(marks) - prev_marks) < 7:
                 ''' guessing the RCB used stack cookies that mimicked rop '''
                 self.lgr.debug('guessing the RCB used stack cookies that mimicked rop ')
                 retval = False
             elif last_instruct is None and 'came from loader' in last_mark:
                 self.lgr.debug('**** found loader in mark ****')
                 print('**** found loader in mark ****')
                 self.lgr.debug('**** found loader in mark ****')
                 fh.write('found loader as source of nox, undo it!\n')
                 retval = False
             else:
                 self.lgr.debug('taintAddr, addTrack')
                 self.analysis_events.addTrack(marks[prev_marks:])
         else:
             self.lgr.debug('taintAddr, no new bookmarks to track')
         return retval

    def taintReg(self, reg, fh):
         prev_marks = len(self.getMarks())
         cmd='@cgc.revTaintReg("%s")\n' % reg
         print('do command %s' % cmd)
         self.lgr.debug('taintReg, do command %s' % cmd)
         self.server_in.write(cmd) 
         self.server_in.flush()
         self.waitUntilMailbox()
         marks = self.getMarks()
         if len(marks) > prev_marks:
             fh.write('Reverse data tracking of content of register %s:\n' % reg)
             self.lgr.debug('Reverse data tracking of content of register %s:\n' % reg)
             self.analysis_events.addTrack(marks[prev_marks:])
             for mark in marks[prev_marks:]:
                 line_number = self.getLineNumber(mark)
                 fh.write('\t%s instruction#%d\n' % (mark, line_number))
                 self.lgr.debug('\t%s instruction#%d\n' % (mark, line_number))

    def checkProtected(self, pov, fh):
        protected = self.getLastProtected()
        if protected is not None:
            self.goToBookmark(protected)
            print('checkProtected, back from goto protected')
            self.lgr.debug('checkProtected, back from goto protected')
            eip, instruct = self.getInstruct()
            protected_address = getTagValue(protected, 'protected_memory')
            line_number = self.getLineNumber(protected)
            proof = False
            for mark in self.marks:
                if 'proof' in mark:
                    proof = True
                    break
            fh.write('Type 2 POV, protected memory address %s read\n\t%s Had proof? %r %s\n' % (protected_address, eip, proof, instruct))
            self.lgr.debug('Type 2 POV, protected memory address %s read\n\t%s Had proof? %r %s\n' % (protected_address, eip, proof, instruct))
            segv = False
            self.addProtected(eip, instruct, protected_address, proof, line_number)
            rop = self.getFirstROP()
            nox = self.getFirstNOX()
            self.lgr.debug('first rop: %s' % rop)
            self.lgr.debug('first nox: %s' % nox)
            if rop is None and nox is None:
                ''' no apparent control flow corruption, so the source of the magic page address is interesting '''
                self.lgr.debug('no rop or nox, check reg indirect')
                reg = self.getRegIndirect(instruct)
                if reg is not None:
                    self.taintReg(reg, fh) 
            else:
                self.lgr.debug('checkProtected rop and/or nox')
                if rop is not None and not self.did_rop:
                    self.doROP(rop, nox, pov, fh)            
                if nox is not None and not self.did_nox:
                    self.doNOX(nox, rop, fh)
                    ''' special case for bogus nox '''
                    if self.bad_nox:
                        self.goToBookmark(protected)
                        reg = self.getRegIndirect(instruct)
                        if reg is not None:
                            self.lgr.debug('checkProtected special case indirect')
                            self.analysis_events.trackProtected()
                            self.taintReg(reg, fh) 
            xmit_from_page = False
            if instruct == 'int 128':        
                xmit_from_page = True
            if xmit_from_page and not self.checkProtectedTransmit(fh, xmit_from_page) and not (nox is not None and rop is not None):
                self.goToBookmark(protected)
                self.analysis_events.trackProtected()
                self.taintReg('ecx', fh)

            segv = self.getSEGV()
            if segv is not None:
                self.addSEGV('0', '0', '', 0)

            return True
        return False
  
    def isProtectedAddress(self, address):
        for mark in marks:
            if mark.startswith('protected_memory') and address in mark:
                return True
        return False
         
    def checkProtectedTransmit(self, fh, xmit_from_page):
        retval = False
        last = self.getLastProtectedTransmit()
        if last is not None:
            retval = True
            self.goToBookmark(last)
            eip, instruct = self.getInstruct()
            line_number = self.getLineNumber(last)
            memory = getTagValue(last, 'memory')
            value = getTagValue(last, 'value')
            if not self.isProtectedAddress(memory):
                self.analysis_events.addProtectedTransmit(eip, memory, value, line_number, xmit_from_page) 
                fh.write('Transmit protected memory eip:%s  value %s from %s, line # %d\n' % (eip, value, memory, line_number))
                if not xmit_from_page:
                    address = int(memory, 16)
                    self.taintAddr(memory, fh)
                else:
                    self.taintReg('ecx', fh)
        return retval
    
    def doNOX(self, nox, rop, fh):
        self.lgr.debug('in doNOX')
        line_number = self.getLineNumber(nox)
        if rop is None:
            ''' perhaps a call [reg] corrupted execution flow '''
            self.lgr.debug('call to lookForCall')
            self.lookForCall(nox, fh)
        self.goToBookmark(nox)
        eip, instruct = self.getInstruct()
        fh.write('Execution of nox at eip:%s inst:"%s" instruction #%d  Where did that code come from?\n' % (eip, instruct, line_number))
        self.lgr.debug('Execution of nox at eip:%s inst:"%s" instruction #%d  Where did that code come from?\n' % (eip, instruct, line_number))
        self.addNOX(eip, instruct, line_number)
        if self.taintAddr(eip, fh):
            self.did_nox = True
        else:
            self.lgr.debug('undoing NOX')
            self.undoNOX()
            self.bad_nox = True

    def doROP(self, rop, nox, pov, fh):
        self.lgr.debug('in doROP')
        line_number = self.getLineNumber(rop)
        self.goToBookmark(rop)
        esp = self.getRegValue('esp')
        eip = self.getRegValue('eip')
        dest_addr = getTagValue(rop, 'rop')
        fh.write('Execution path corruption at eip:%s, return to address:%s esp was:%s insruction#%d\n' % (eip, 
              dest_addr, esp, line_number))
        self.lgr.debug('Execution path corruption at eip:%s, return to address:%s esp was:%s insruction#%d\n' % (eip, 
              dest_addr, esp, line_number))

        self.addControlCorruptReturn(eip, dest_addr, esp, line_number)
        if esp is not None:
            if not self.taintAddr(esp, fh):
                fh.write('UNDO -- no execution path corruption, may be stack cookie-like RCB')
                self.undoCorruptReturn()

        if nox is None and pov is not None:
            self.goToBookmark(pov)
            address, instruct = self.getInstruct()
            if instruct.startswith('ret'):
                line_number = self.getLineNumber(pov)
                eip = self.getRegValue('eip')
                esp = self.getRegValue('esp')
                fh.write('SEGV due to bad return address, backtrack to source of retrun address\n')
                self.addSEGV(eip, esp, instruct, line_number)
                self.taintAddr(esp, fh)
        self.did_rop = True

    def checkGeneral(self, pov, fh):
         reg, value = self.analysis_events.getGeneral()
         if reg is not None:
             fh.write('General register %s, track source of its value: %s' % (reg, value))
             self.goToBookmark(pov)
             self.taintReg(reg, fh)

    def addNOX(self, eip, instruct, line_number):
         self.analysis_events.addNOX(eip, instruct, line_number)

    def addControlCorruptReturn(self, eip, ret_addr, esp, instruction_number):
         self.analysis_events.addControlCorruptReturn(eip, ret_addr, esp, instruction_number)

    def undoControlCorruptReturn(self):
         self.analysis_events.undoControlCorruptReturn()
         self.bad_rop = True

    def addControlCorruptCall(self, eip, inst, call_to, instruction_number):
         self.analysis_events.addControlCorruptCall(eip, inst, call_to, instruction_number)

    def addPOV(self, pov_mark, instruction_number, fh):
        if not self.checkProtected(pov_mark, fh):
            self.analysis_events.addPOV(pov_mark, instruction_number)

    def addSEGV(self, eip, esp, inst, line_number):
        self.analysis_events.addSEGV(eip, esp, inst, line_number)

    def addType1Track(self):
        self.analysis_events.addType1Track()

    def addProtected(self, eip, inst, protected_address, proof, instruction_number):
        self.analysis_events.addProtected(eip, inst, protected_address, proof, instruction_number)

    def getThrowId(self):        
        return self.throw_id

    def getJson(self):
        return self.analysis_events.dumpJson()

    def noEvent(self):
        self.analysis_events.noEvent()

    def undoCorruptReturn(self):
        self.analysis_events.undoCorruptReturn()

    def undoNOX(self):
        self.analysis_events.undoNOX()

    def reloadCkpt(self):
      print('about to reload checkpoint')
      self.lgr.debug('about to reload checkpoint')
      cmd = 'restart-simics ready4monitor.ckpt\n'
      self.server_in.write(cmd)
      self.server_in.flush()
      print('back from reload checkpoint wait a bit')
      self.lgr.debug('back from reload checkpoint wait a bit')
      time.sleep(5)
      #cmd = 'run-python-file cgcMonitor.py\n'
      #self.server_in.write(cmd)
      #self.server_in.flush()
      print('call doWhitelist')
      cmd = 'run-python-file doWhitelist.py\n'
      self.server_in.write(cmd)
      self.server_in.flush()
      print('back from doWhitelist')
      self.lgr.debug('back from doWhitelist')
      #cmd='continue\n'
      #self.server_in.write(cmd)
      #self.server_in.flush()

if __name__ == '__main__':    
    print('start autoClient')
    simics_stdin = 'simics.stdin'
    simics_stdout = 'simics.stdout'
    cfg = configMgr.configMgr()
    cwd = os.getcwd() 
    my_space = cwd[(len(cwd)-1):]
    my_name = 'auto_analysis_%s' % my_space
    lgr = utils.getLogger(my_name, cfg.logdir)
    lgr.debug('start autoClient')
    try:
       makedirs(cfg.auto_analysis_dir)
    except:
       print('failed makedirs of %s' % cfg.auto_analysis_dir)
       lgr.debug('failed makedirs of %s' % cfg.auto_analysis_dir)
       pass
    try:
        os.mkfifo(simics_stdin)
        os.mkfifo(simics_stdout)
    except OSError as oe:
        if os.errno != errno.EEXIST:
            raise
    with open(simics_stdin, 'a') as server_in:
      sys.stderr.write('client fifo to simics stdin is open\n')
      server_out = open(simics_stdout, 'ro')
      if len(sys.argv) == 1 or sys.argv[1] != 'auto':
          ''' auto analysis not requested, just server as echo of server stdout '''
          while True:
              line = server_out.readline()
              if len(line) == 0:
                  print('autoClient got empty line from server output, exit')
                  lgr.error('autoClient got empty line from server output, exit')
                  exit(0)
              print line 
      ac = autoClient(server_in, server_out, lgr)
      while True:
        got_event = ac.waitForReady()
        sys.stderr.write('got autoanalysis is ready\n')
        throw_id = ac.getThrowId()
        if throw_id is not None:
            fname = os.path.join('/tmp', throw_id+'-analysis.txt')
            fh = open(fname, 'w') 
        else:
            fh = open('myanalysis.txt', 'w')
        replay = ac.getDebugReplay()
        fh.write('Auto analysis for %s\n' % replay)
        if not got_event:
            fh.write('No event found\n')
            ac.noEvent()
        else: 
            marks = ac.getMarks()
            for mark in marks:
                fh.write('\t%s\n' % mark)
            pov = ac.getPOV()
            if pov is not None:
                line_number = ac.getLineNumber(pov)
                if 'Signal 11' in pov:
                    protected = ac.getLastProtected()
                    if protected is not None: 
                        fh.write('SEGV, perhaps following a Type 2 POV: %s\n' % protected)
                    else:
                        fh.write('SEGV, no Type 2 negotiated\n')
                    ac.goToBookmark(pov)
                    esp = ac.getRegValue('esp')
                    eip, inst = ac.getInstruct()
                    fh.write('SEGV at eip:%s, esp was:%s   %s\n' % (eip, esp, inst))
                    ac.addSEGV(eip, esp, inst, line_number)
                else:
                    fh.write('Start analysis for: %s instruction # %d\n' % (pov, line_number))
                ac.addPOV(pov, line_number, fh)
                rop = ac.getFirstROP()
                nox = ac.getFirstNOX()
                if rop is not None and not ac.did_rop:
                    sys.stderr.write('Do rop from pov')
                    ac.doROP(rop, nox, pov, fh)            
                if nox is not None and not ac.did_nox:
                    ac.doNOX(nox, rop, fh)
                elif rop is None and 'SEGV' in pov:
                    ''' no rop or nox '''
                    ac.goToBookmark(pov)
                    esp = ac.getRegValue('esp')
                    eip, inst = ac.getInstruct()
                    fh.write('SEGV at eip:%s, esp was:%s   %s\n' % (eip, esp, inst))
                    ac.addSEGV(eip, esp, inst, line_number)
                    if inst.startswith('ret'):
                        ac.taintAddr(esp, fh)
                elif rop is None:
                    ''' type 1 pov with no rop or nox '''
                    ac.goToBookmark(pov)
                    esp = ac.getRegValue('esp')
                    eip, inst = ac.getInstruct()
                    if inst.startswith('ret'):
                        ac.addType1Track()
                        ac.taintAddr(esp, fh)
                    elif inst.startswith('call'):
                        reg = inst.split(' ')[1]
                        if reg in ia32_regs:
                            ac.taintCall(reg, eip, inst, line_number, fh)
    
                ac.checkGeneral(pov, fh)
    
            else:
                ''' no pov in entry '''
                ac.checkProtected(pov, fh)
        fh.close()            
        s = ac.getJson()
        json_fh = None
        fname=None
        if throw_id is not None:
            fname = os.path.join('/tmp', throw_id+'-analysis.json')
            json_fh = open(fname, 'w') 
        else:
            json_fh = open('myanalysis.json', 'w')
        json_fh.write(s)
        json_fh.close()
        ac.idaDone()
        ac.reloadCkpt()
        #cmd = 'run-python-file doWhitelist.py\n'
        #server_in.write(cmd)
        #server_in.flush()
        if throw_id is not None:
            dest = os.path.join(cfg.auto_analysis_dir, os.path.basename(fname))
            try:
                shutil.copyfile(fname, dest)
            except:
                print('copy of %s to %s failed' % (fname, dest))
                lgr.error('copy of %s to %s failed' % (fname, dest))
        
