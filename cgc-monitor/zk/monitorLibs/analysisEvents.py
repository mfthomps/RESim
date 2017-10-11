#!/usr/bin/env python
import os
import sys
import json
import shlex
def getTagValue(line, find_tag):
    #parts = line.split()
    parts = shlex.split(line)
    for part in parts:
        if ':' in part:
            tag, value = part.split(':',1)
            if tag.strip() == find_tag:
                return value
    return None

class analysisEvents():
    def __init__(self, throw_id=None, trace_cycles=None):
        self.events = {}
        self.latest_event = None
        self.trace_cycles = trace_cycles
        throw_info = {}
        if throw_id is not None:
            parts = throw_id.split('-')
            throw_info['csid'] = parts[0]
            throw_info['throw_team'] = parts[1]
            throw_info['defend_team'] = parts[2]
            throw_info['round'] = parts[3]
            throw_info['throw_number'] = parts[4]
            first_syscall = trace_cycles.getFirstSyscall()
            throw_info['first_syscall']=first_syscall
            self.events['throw_info'] = throw_info 

    def addPOV(self, pov_mark, instruction_number):
        pov_event = {}
        eip = getTagValue(pov_mark, 'eip')
        if "Type 1" in pov_mark:
            pov_event['type'] = 1
            general = pov_mark.split()[4].strip() 
            pov_event['eip'] = eip
            pov_event['general'] = general
            pov_event['instr_num'] = instruction_number
            self.events['pov'] = pov_event

    def addType1Track(self):
            self.latest_event = self.events['pov']
 
    def getGeneral(self):
        if 'pov' in self.events and 'general' in self.events['pov']:
            general = self.events['pov']['general']
            reg, value = general.split(':')
            gen_event = {}
            self.latest_event = gen_event
            self.events['general_reg'] = gen_event
            return reg, value
        else:
            return None, None

    def addSEGV(self, eip, esp, inst, instruction_number):
        segv_event = {}
        segv_event['eip'] = eip
        segv_event['esp'] = esp
        segv_event['inst'] = inst
        segv_event['instr_num'] = instruction_number
        self.latest_event = segv_event
        self.events['segv'] = segv_event

    def addControlCorruptReturn(self, eip, ret_addr, esp, instruction_number):
        ret_event = {}
        ret_event['eip'] = eip
        ret_event['ret_addr'] = ret_addr
        ret_event['esp'] = esp
        ret_event['instr_num'] = instruction_number
        self.latest_event = ret_event
        self.events['control_corrupt_return'] = ret_event

    def undoControlCorruptReturn(self):
        del self.events['control_corrupt_return']
        self.latest_event = None

    def undoNOX(self):
        del self.events['no_execute']
        self.latest_event = None

    def addControlCorruptCall(self, eip, inst, call_to, instruction_number):
        call_event = {}
        call_event['eip'] = eip
        call_event['call_to'] = call_to
        call_event['inst'] = inst
        call_event['instr_num'] = instruction_number
        self.latest_event = call_event
        self.events['control_corrupt_call'] = call_event

    def addNOX(self, eip, inst, instruction_number):
        nox_event = {}
        nox_event['eip'] = eip
        nox_event['inst'] = inst
        nox_event['instr_num'] = instruction_number
        self.latest_event = nox_event
        self.events['no_execute'] = nox_event

    def addProtected(self, eip, inst, protected_address, proof, instruction_number):
        protected_event = {}
        protected_event['type'] = 2
        protected_event['eip'] = eip
        protected_event['inst'] = inst
        protected_event['protected_address'] = protected_address
        if proof:
            protected_event['proof'] = True
        protected_event['instr_num'] = instruction_number
        self.events['pov'] = protected_event 
        self.latest_event = protected_event

    def trackProtected(self):
        self.latest_event = self.events['pov']
       
    def addProtectedTransmit(self, eip, memory, value, instruction_number, xmit_from_page):
        ptr_event = {}
        ptr_event['eip'] = eip
        ptr_event['memory'] = memory
        ptr_event['value'] = value
        ptr_event['xmit_from_page'] = xmit_from_page
        ptr_event['instr_num'] = instruction_number
        self.latest_event = ptr_event
        self.events['protected_transmit'] = ptr_event

    def noEvent(self):
        self.events['no_event'] = ""

    def dumpJson(self): 
        s = json.dumps(self.events)
        print('json:\n%s' % s)
        return s
 
    def addTrack(self, track):
        track_event = {}
        start = track[0]
        track_event['from_eip'] = getTagValue(start,'START')
        track_event['inst'] = getTagValue(start, 'inst')
        if 'track_addr' in start:
            track_event['track_addr'] = getTagValue(start, 'track_addr')
            track_event['track_value'] = getTagValue(start, 'track_value')
        elif 'track_reg' in start:
            track_event['track_reg'] = getTagValue(start, 'track_reg')
            track_event['track_value'] = getTagValue(start, 'track_value')
        flow = []
        for mark in track[1:]:
            flow_event = {}
            flow_event['eip'] = getTagValue(mark, 'eip')
            inst = getTagValue(mark, 'inst')
            if inst is None:
                if 'kernel write' in mark:
                    inst = 'receive syscall (return)' 
                elif 'loader' in mark:
                    inst = 'cgc loader'
            flow_event['inst'] = inst
            cycle = getTagValue(mark, 'cycle')
            if self.trace_cycles is not None:
                flow_event['inst_num'] = self.trace_cycles.getLineNumber(cycle)
            flow.append(flow_event)
        track_event['flow'] = flow
        if self.latest_event is not None:
            self.latest_event['track'] = track_event
        else:
            print('*** ERROR ***, call to add track but no such event registered ****')
            exit(1) 


    def load(self, fh):
        j = json.load(fh)
        self.events = j

    def trackToString(self, track):
        if 'track_addr' in track:
            print('\tReverse data track from eip:%s tracking source of memory:%s value:%s' % (track['from_eip'], track['track_addr'], track['track_value']))
        elif 'track_reg' in track:
            print('\tReverse data track from eip:%s tracking source of register:%s value:%s' % (track['from_eip'], track['track_reg'], track['track_value']))
        for flow_event in track['flow']:
            print('\t\t%s   %-40s; %d' % (flow_event['eip'], flow_event['inst'], flow_event['inst_num'])) 
         
    def toString(self):
        if 'throw_info' in self.events:
            throw_info = self.events['throw_info']
            print('Automated analysis results for csid: %s throw_team: %s  defend_team: %s  round: %s  throw_number: %s first_syscall: %d' % (throw_info['csid'],
                throw_info['throw_team'], throw_info['defend_team'], throw_info['round'], throw_info['throw_number'], throw_info['first_syscall']))

        if 'pov' in self.events:
            pov_event = self.events['pov']
            if pov_event['type'] == 1:
                print('POV Type 1  eip:%s %s  instruction_number: %d' % (pov_event['eip'], pov_event['general'],
                    pov_event['instr_num']))

                if 'track' in pov_event:
                    self.trackToString(pov_event['track'])

            elif pov_event['type'] == 2:
                print('POV Type 2  eip:%s %s  read from %s  instruction_number: %d' % (pov_event['eip'], pov_event['inst'],
                    pov_event['protected_address'], pov_event['instr_num']))

        if 'control_corrupt_return' in self.events:
           ret_event = self.events['control_corrupt_return']
           print('Execution control corruption eip:%s  return to address:%s  esp:%s  instruction_num:%d' % ( ret_event['eip'], 
               ret_event['ret_addr'], ret_event['esp'], ret_event['instr_num']))
           self.trackToString(ret_event['track'])

        if 'control_corrupt_call' in self.events:
           ret_event = self.events['control_corrupt_call']
           print('Execution control corruption eip:%s  instr:"%s" call_to:%s  instruction_num:%d' % ( ret_event['eip'], 
               ret_event['inst'], ret_event['call_to'], ret_event['instr_num']))
           self.trackToString(ret_event['track'])

        if 'no_execute' in self.events:
            nox_event = self.events['no_execute']
            print('NOX at eip:%s  "%s" instruction_num:%d  -- source of payload:' % (nox_event['eip'], nox_event['inst'], 
                nox_event['instr_num']))
            self.trackToString(nox_event['track'])
       
        if 'general_reg' in self.events:
            gen_event = self.events['general_reg']
            print('Negotiated general register: %s, backtrack to source of that value' % (self.events['pov']['general']))
            self.trackToString(gen_event['track'])

        if 'protected_transmit' in self.events:
            ptr_event = self.events['protected_transmit']
            print('Transmit protected memory value:%s from memory:%s  instruction_num:%d -- backtrack flow of protected data follows:' % (ptr_event['value'],
                ptr_event['memory'], ptr_event['instr_num']))
            self.trackToString(ptr_event['track'])

if __name__ == '__main__':    
   '''
   pov_mark='Type 1 POV eip:0x508ca5bf eax:0xb98d9efc cycle:5e24fac'
   ae = analysisEvents(None)
   ae.addPOV(pov_mark, 81442)
   marks = []
   marks.append('backtrack START:0x804866b inst:"ret" track_addr:0xbaaaaf48 trac_value:0xbaaaaf2d cycle:5e24fa9')
   marks.append('backtrack eip:0x8048338 inst:"mov dword ptr [ebp+edx*4-0x58],eax" cycle:5c5c87e')
   marks.append('backtrack eip:0x80498e9 follows kernel write of value:0xf0ab8 to memory:0xbaaaae2e cycle:5c5e919')

   ae.addControlCorruptReturn('0x804866b', '0xbaaaaf2d', '0xbaaaaf48', 81439)
   ae.addTrack(marks)
   ae.dumpJson()
   '''
   ae = analysisEvents()
   with open(sys.argv[1]) as fh:
       ae.load(fh)
       ae.toString()
            
