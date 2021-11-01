#!/usr/bin/env python3
'''
Read a data track json and return the sequence of
input data references.
'''
import os
import sys
import json
import struct
def findOrig(ref_addr, refs, orig_addr, orig_len):
    retval = None
    #print('find ref_addr for 0x%x' % ref_addr)
    for addr in refs:
        if ref_addr == addr: 
            if refs[addr] >= orig_addr and refs[addr] < (orig_addr+orig_len):
                retval = refs[addr]
                break
            else:
                #print('matched ref[0x%x], but that is not within original buffer, look for 0x%x' % (addr, refs[addr]))
                retval = findOrig(refs[addr], refs, orig_addr, orig_len) 
                break
    return retval

def isMod(mark, offset, mods):
    retval = False
    if mark['reference_buffer'] in mods:
        if offset in mods[mark['reference_buffer']]:
            retval = True
    return retval

class ReadMark():
    def __init__(self, offset, size, data, ip, cycle, packet):
        self.offset = offset
        self.size = size
        self.data = data
        self.ip = ip
        self.cycle = cycle
        self.packet = packet

def getReadMarks(jpath):
    ''' jpath is path to the trackio '''
    base = os.path.basename(jpath)
    track = os.path.dirname(jpath)
    target = os.path.dirname(track)
    queue_file = os.path.join(target, 'queue', base)
    
    session_data = None
    file_len = 0
    with open(queue_file, 'rb') as fh:
        session_data = fh.read()
        file_len = len(session_data)
        #print('session data is %s' % session_data)
  
    read_marks = []
    if not os.path.isfile(jpath):
        print('Missing file: %s' % jpath)
        return None, None
    trackdata = json.load(open(jpath))
    ''' Support tracking data references back to their original buffer location '''
    refs = {}
    ''' Identify which data offsets have been modified (written to) '''
    mods = {}
    orig_addr = None 
    for mark in trackdata:
        ''' TBD expand to handle calls and source addresses '''
        if mark['mark_type'] == 'call' and orig_addr is None:
            orig_addr = mark['recv_addr']
            orig_len = mark['length']
            #print('original addr 0x%x : %d' % (orig_addr, orig_len))
    
        if mark['mark_type'] == 'copy':
            if mark['reference_buffer'] != orig_addr:
                orig = findOrig(mark['reference_buffer'], refs, orig_addr, orig_len)
                if orig is None:
                    print('copy, COULD NOT FIND original buffer for 0x%x' % mark['reference_buffer'])
                else:
                    if mark['src'] in refs and refs[mark['src']] == mark['dest']:
                        print('mark[0x%x] already in refs and that equals the dest. Looks like a copy-back, skipping dest 0x%x.' % (mark['src'], mark['dest']))
                    else:
                        refs[mark['dest']] = mark['src'] 
                        orig_offset = orig - orig_addr
                        offset = mark['src'] - mark['reference_buffer']
                        tot_offset = orig_offset + offset
                        #print('copy %d bytes from offset %d  new ref[0x%x] = 0x%x' % (mark['length'], tot_offset, mark['dest'], mark['src']))
                 
            else:
                ''' original buffer, so (src - orig_addr)  is the offset into the original.'''
                refs[mark['dest']] = mark['src'] 
                offset = mark['src'] - orig_addr
                #print('copy %d bytes from offset %d  new ref[0x%x] = 0x%x' % (mark['length'], offset, mark['dest'], mark['src']))

        if mark['mark_type'] == 'scan':
            if mark['reference_buffer'] != orig_addr:
                orig = findOrig(mark['reference_buffer'], refs, orig_addr, orig_len)
                if orig is None:
                    print('copy, COULD NOT FIND original buffer for 0x%x' % mark['reference_buffer'])
                else:
                    if mark['src'] in refs and refs[mark['src']] == mark['dest']:
                        print('mark[0x%x] already in refs and that equals the dest. Looks like a copy-back, skipping dest 0x%x.' % (mark['src'], mark['dest']))
                    else:
                        refs[mark['dest']] = mark['src'] 
                        orig_offset = orig - orig_addr
                        offset = mark['src'] - mark['reference_buffer']
                        tot_offset = orig_offset + offset
                        print('scan %d bytes from offset %d  new ref[0x%x] = 0x%x' % (mark['length'], tot_offset, mark['dest'], mark['src']))
                 
            else:
                ''' original buffer, so (src - orig_addr)  is the offset into the original.'''
                refs[mark['dest']] = mark['src'] 
                offset = mark['src'] - orig_addr
                print('scan %d bytes from offset %d  new ref[0x%x] = 0x%x' % (mark['length'], offset, mark['dest'], mark['src']))

        if mark['mark_type'] == 'sprint':
            if mark['reference_buffer'] != orig_addr:
                orig = findOrig(mark['reference_buffer'], refs, orig_addr, orig_len)
                if orig is None:
                    print('copy, COULD NOT FIND original buffer for 0x%x' % mark['reference_buffer'])
                else:
                    if mark['src'] in refs and refs[mark['src']] == mark['dest']:
                        print('mark[0x%x] already in refs and that equals the dest. Looks like a copy-back, skipping dest 0x%x.' % (mark['src'], mark['dest']))
                    else:
                        refs[mark['dest']] = mark['src'] 
                        orig_offset = orig - orig_addr
                        offset = mark['src'] - mark['reference_buffer']
                        tot_offset = orig_offset + offset
                        print('sprint %d bytes from offset %d  new ref[0x%x] = 0x%x' % (mark['length'], tot_offset, mark['dest'], mark['src']))
                 
            else:
                ''' original buffer, so (src - orig_addr)  is the offset into the original.'''
                refs[mark['dest']] = mark['src'] 
                offset = mark['src'] - orig_addr
                print('sprint %d bytes from offset %d  new ref[0x%x] = 0x%x' % (mark['length'], offset, mark['dest'], mark['src']))
        
        if mark['mark_type'] == 'read':
            if mark['reference_buffer'] == orig_addr:
                offset = mark['addr'] - orig_addr
                if isMod(mark, offset, mods):
                    #print('read %d offset %d [mod]' % (mark['trans_size'], offset))
                    pass
                else:
                    #print('read %d offset %d' % (mark['trans_size'], offset))
                    size = mark['trans_size']
                    data = int.from_bytes(session_data[offset:offset+size], byteorder='big')
                    #data = struct.unpack("i", ba)[0]
                    read_mark = ReadMark(offset, mark['trans_size'], data, mark['ip'], mark['cycle'], mark['packet'])
                    read_marks.append(read_mark)
            else:
                orig = findOrig(mark['reference_buffer'], refs, orig_addr, orig_len)
                if orig is None:
                    print('read, COULD NOT FIND original buffer for 0x%x' % mark['reference_buffer'])
                else:
                    orig_offset = orig - orig_addr
                    offset = mark['addr'] - mark['reference_buffer']
                    tot_offset = orig_offset + offset
                    if isMod(mark, offset, mods):
                        #print('read %d offset %d [mod]' % (mark['trans_size'], tot_offset))
                        pass
                    else:
                        #print('read %d offset %d' % (mark['trans_size'], tot_offset))
                        size = mark['trans_size']
                        data = int.from_bytes(session_data[tot_offset:tot_offset+size], byteorder='big')
                        read_mark = ReadMark(offset, mark['trans_size'], data, mark['ip'], mark['cycle'], mark['packet'])
                        read_marks.append(read_mark)
     
        if mark['mark_type'] == 'write' and mark['addr'] is not None:
            if mark['reference_buffer'] not in mods:
                mods[mark['reference_buffer']] = []
            if mark['reference_buffer'] == orig_addr:
                offset = mark['addr'] - orig_addr
            else:
                offset = mark['addr'] - mark['reference_buffer']
       
            for i in range(mark['trans_size']): 
                mods[mark['reference_buffer']].append(offset+i)
        if mark['mark_type'] == 'compare':
            print('compare')


    return read_marks, file_len

