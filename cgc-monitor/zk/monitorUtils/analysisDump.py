#!/usr/bin/env python
import sys
import json
def getTagValue(line, find_tag):
    #parts = line.split()
    parts = shlex.split(line)
    for part in parts:
        if ':' in part:
            tag, value = part.split(':',1)
            if tag.strip() == find_tag:
                return value
    return None

class analysisDump():
    def __init__(self):
        self.events = {}
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
                lacks_proof = ''
                if 'proof' not in pov_event:
                    lacks_proof = 'lacks proof'
                print('POV Type 2  eip:%s %s  read from %s  %s instruction_number: %d' % (pov_event['eip'], pov_event['inst'],
                    pov_event['protected_address'], lacks_proof, pov_event['instr_num']))
                if 'track' in pov_event:
                    self.trackToString(pov_event['track'])

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
            if not ptr_event['xmit_from_page']:
                print('Transmit protected memory value:%s from memory:%s  instruction_num:%d -- backtrack flow of protected data follows:' % (ptr_event['value'],
                    ptr_event['memory'], ptr_event['instr_num']))
            else:
                print('Transmit protected memory value:%s from protected memory:%s  instruction_num:%d -- backtrack flow of address of protected memory follows:' % (ptr_event['value'],
                    ptr_event['memory'], ptr_event['instr_num']))
            self.trackToString(ptr_event['track'])

        if 'no_event' in self.events:
            print('No event found.')

    def load(self, fh):
        j = json.load(fh)
        self.events = j


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
   ae = analysisDump()
   with open(sys.argv[1]) as fh:
       ae.load(fh)
       ae.toString()
            
