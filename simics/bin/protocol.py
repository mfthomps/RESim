#!/usr/bin/env python3
'''
Read a data track json and display memory references and copies
with offsets relative to the input buffer.  Partial identification
of references to potentially modified memory.
'''
import os
import sys
import json
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

jpath = '/tmp/track.json'

trackdata = json.load(open(jpath))
''' Support tracking data references back to their original buffer location '''
refs = {}
''' Identify which data offsets have been modified (written to) '''
mods = {}

orig_addr = None
for mark in trackdata:
    #print('mark type %s' % mark['mark_type'])
    if mark['mark_type'] == 'call' and orig_addr is None:
        orig_addr = mark['recv_addr']
        orig_len = mark['length']
        print('original addr 0x%x : %d' % (orig_addr, orig_len))

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
                    print('copy %d bytes from offset %d  new ref[0x%x] = 0x%x' % (mark['length'], tot_offset, mark['dest'], mark['src']))
             
        else:
            ''' original buffer, so (src - orig_addr)  is the offset into the original.'''
            refs[mark['dest']] = mark['src'] 
            offset = mark['src'] - orig_addr
            print('copy %d bytes from offset %d  new ref[0x%x] = 0x%x' % (mark['length'], offset, mark['dest'], mark['src']))
    
    if mark['mark_type'] == 'read':
        if mark['reference_buffer'] == orig_addr:
            offset = mark['addr'] - orig_addr
            if isMod(mark, offset, mods):
                print('read %d offset %d [mod]' % (mark['trans_size'], offset))
            else:
                print('read %d offset %d' % (mark['trans_size'], offset))
        else:
            orig = findOrig(mark['reference_buffer'], refs, orig_addr, orig_len)
            if orig is None:
                print('read, COULD NOT FIND original buffer for 0x%x' % mark['reference_buffer'])
            else:
                orig_offset = orig - orig_addr
                offset = mark['addr'] - mark['reference_buffer']
                tot_offset = orig_offset + offset
                if isMod(mark, offset, mods):
                    print('read %d offset %d [mod]' % (mark['trans_size'], tot_offset))
                else:
                    print('read %d offset %d' % (mark['trans_size'], tot_offset))
 
    if mark['mark_type'] == 'write':
        if mark['reference_buffer'] not in mods:
            mods[mark['reference_buffer']] = []
        if mark['reference_buffer'] == orig_addr:
            offset = mark['addr'] - orig_addr
        else:
            offset = mark['addr'] - mark['reference_buffer']
   
        for i in range(mark['trans_size']): 
            mods[mark['reference_buffer']].append(offset+i)




