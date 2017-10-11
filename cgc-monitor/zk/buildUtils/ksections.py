#!/usr/bin/python
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
from os import listdir
import sys
import subprocess
import shlex
import glob

'''
NO PRINTS with out #, output goes to ksections.cfg
Get the kernel text, text_size, text2 and text_size2 values for a simics monitor
Gets text size from the /boot/System-map... and uses lsmodule with the files in /sys/module/*/sections/.text
'''
def moduleSize(module):
    grep = 'grep "%s"' % module
    proc1 = subprocess.Popen(shlex.split('lsmod'),stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(shlex.split(grep),stdin=proc1.stdout,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    
    proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
    out,err=proc2.communicate()
    #print('out: {0}'.format(out))
    #print('err: {0}'.format(err))
    offset = out.split()
    return int(offset[1], 16)
def getKernelText(map):
    start = None
    length = None
    with open(map, 'rb') as f_in:
        for l in f_in:
            addr, t, sym =  l.strip().split()
            if sym == '_text':
                print('#start %s' % l)
                start = int(addr, 16)
            if sym == '__bss_start':
                print('#end %s' % l)
                end = int(addr, 16)
                length = end - start
    return start, length

top = '/sys/module'
dirs = listdir(top)
uname = sys.argv[1]
highest = 0
lowest = 0xffffffff
if uname == "Linux64":
    lowest = 0xffffffffffffffff
top_module = None
for dir in dirs:
    #print '%s' % dir
    text = top+'/'+dir+'/sections/.text'
    f = None
    try:
        f = open(text, 'r')
    except:
        continue
    s = f.read()
    #print '%s' % s
    f.close()
    addr = int(s, 16)
    if addr < lowest:
        lowest = addr
    if addr > highest:
        highest = addr
        top_module = dir

def usage():
    print("usage: ksections.py uname")
    print("\t where uname is Linux or Linux64")
    exit(1)

if len(sys.argv) != 2:
    usage()
if uname == "Linux":
    files = glob.glob('/boot/System.map*cgc*') 
    if len(files) > 1:
        print('too many system maps to choose from')
        exit(1)
    map = files[0] 
elif uname == "Linux64":
    files = glob.glob('/boot/System.map*amd64*') 
    if len(files) > 1:
        print('too many system maps to choose from')
        exit(1)
    map = files[0] 
else:
    usage()

size = moduleSize(top_module)
print '#highest: %x (%s) size: %x  lowest %x' % (highest, top_module, size, lowest)

highest_code = highest+size
#print 'highest code is %x' % highest_code
code_size = highest_code - lowest
#print 'code_size is %x' % code_size
text2 = lowest
text2_size = code_size
text, text_size = getKernelText(map)
print '#add the following to the master.cfg file:'
print '[kernel]'
print 'text=%x' % text
print 'text_size=%x' % text_size
print 'text2=%x' % text2
print 'text2_size=%x' % text2_size
