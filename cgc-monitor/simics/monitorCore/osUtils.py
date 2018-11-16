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

import os
import simics
'''
   Return either bsdUtils or linuxUtils along with the corresponding parameter file
'''
''' These are sytem configuration choices '''
# decree
LINUX='linux'
# stock linux64
LINUX64='linux64'
# kangaroo
FREE_BSD='freeBSD'
FREE_BSD64='freeBSD64'

# kangaroo<==>linux64<===>kangaroo (klk)
MIXED_KLK='mixed_klk'
MIXED_KLK64='mixed_klk64'

# decree<==>linux64<===>decree (dld)
MIXED_DLD='mixed_dld'

# linux64<==>linux64<===>kangaroo (llk)
MIXED_LLK='mixed_llk'
MIXED_LLK64='mixed_llk64'

# linux64<==>linux64<===>decree (lld)
MIXED_LLD='mixed_lld'

params = None
def getOSParams(os_types):
    os_params = {}
    print('getOSParams given %s' % str(os_types))
    for cell_name in os_types:
       if os_types[cell_name] == LINUX: 
           os_params[cell_name] = 'debian.params'
           print('getOSUtils, ostype for %s is %s' % (cell_name, LINUX))
       elif os_types[cell_name] == LINUX64: 
           os_params[cell_name] = 'debian64.params'
           print('getOSUtils, ostype for %s is %s' % (cell_name, LINUX64))
       elif os_types[cell_name] == FREE_BSD64: 
           print('getOSUtils, ostype for %s is %s' % (cell_name, FREE_BSD64))
           os_params[cell_name] = 'freeBSD64.params'
       else:
           print('getOSUtils, ostype for %s is %s' % (cell_name, FREE_BSD))
           os_params[cell_name] = 'freeBSD.params'
          
    return os_params 


    '''
    BSD = os.getenv('BSD')
    if BSD == 'YES':
        return bsdUtils, 'freeBSD.params'
    else:
        params = 'debian.params'
        return linuxUtils, params
    '''
class execStrings():
    def __init__(self, cpu, pid, arg_addr_list, prog_addr, callback):
        self.arg_addr_list = arg_addr_list
        self.prog_addr = prog_addr
        self.cpu = cpu
        self.pid = pid
        self.callback = callback
        self.prog_name = None
        self.arg_list = None

def loadParameters(filename):
    p_file = simics.SIM_lookup_file(filename)
    if p_file is None:
        print 'Unable to open settings file (%s)' % filename
        return
    s = open(p_file, 'r').read()
    settings = eval(s)
    return settings, p_file

def getSigned(iv):
    if(iv & 0x80000000):
        iv = -0x100000000 + iv
    return iv

