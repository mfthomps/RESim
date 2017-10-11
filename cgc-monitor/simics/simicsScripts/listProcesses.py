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

from simics import *
import mod_software_tracker_commands as tr
import sys
lib = "/home/mike/simics-4.6/simics-4.6.84/linux64/lib/"
if lib not in sys.path:
    sys.path.append(lib)
tracker = '%s/software-tracker' % lib
if tracker not in sys.path:
    sys.path.append(tracker)
if tracker not in sys.path:
    sys.path.append(tracker)
here = '/mnt/cgc/simics/simicsScripts'
if here not in sys.path:
    sys.path.append(here)
here = '/mnt/cgc/zk/py'
if here not in sys.path:
    sys.path.append(here)
import freeBSD_common
import osUtils

os, params, os_type = osUtils.getOSUtils()
''' Kernel offsets, e.g., where is the comm field in a proc record? '''
settings = os.loadParameters(params)
param = freeBSD_common.Parameters.from_attr_val(settings[1])
'''
cmd = '%s.get-processor-list' % sys.argv[1]
print 'command is %s' % cmd
proclist = SIM_run_command(cmd)
cpu = SIM_get_object(proclist[0])
'''
cpu = SIM_current_processor()
plist = os.getProcList(param, cpu)
tab = 7
for pi in plist:
   if len(pi.comm) == 0:
       break
   if len(pi.comm) >= tab:
       tabs = '\t'
   else:
       tabs = '\t\t'
   tinfo = ''
   if pi.tlist is not None:
       for ti in pi.tlist:
           tinfo = tinfo + '%s %d %d %d' % (ti.comm, ti.pid, ti.euid, ti.ruid)
   print '%s %s%d \t%d \t%d\t%s' % (pi.comm, tabs, pi.pid, pi.euid, pi.ruid, tinfo)
