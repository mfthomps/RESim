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

import simics
import sys
import os
'''
Generate a trace after reaching a eip given as an environment variable
'''
def postEvent(cpu):
    global cycle_event
    global num_instructs
    global start_cycle
    start_cycle = SIM_cycle_count(cpu)
    print('in postEvent at start_cycle 0x%x' % start_cycle)
    SIM_event_post_cycle(cpu, cycle_event, cpu, num_instructs, num_instructs)

def cycle_handler(obj, cycles):
    ''' avoid packageMgr timeouts for things like rop on big xml validation'''
    global start_cycle
    cycle = SIM_cycle_count(cpu)
    dif = cycle - start_cycle 
    print('in cycle_handler at cycle 0x%x, dif is %d' % (cycle, dif))
    cmd = '%s.stop' % tracer
    SIM_run_alone(SIM_run_command, cmd)
    SIM_break_simulation('done')
    print('Done')
    #SIM_run_command('quit')

def startTrace(cpu, third, forth, memory):
    global hap
    global cycle_event
    global break_eip
    global page_hap
    if hap is None:
        return
    print('in the HAP')
    cmd = '%s.start file=%s' % (tracer, outfile)
    SIM_run_alone(SIM_run_command, cmd)
    print('register the event')
    cycle_event = SIM_register_event("waitForSSH cycle event", SIM_get_class("sim"), Sim_EC_Notsaved, cycle_handler, None, None, None, None)
    postEvent(cpu)
    SIM_delete_breakpoint(break_eip)
    SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hap)
    hap = None
    break_eip = None
    gdtr_base = cpu.gdtr_base
    reg_num = cpu.iface.int_register.get_number("gs")
    gs = cpu.iface.int_register.read(reg_num)
    print('set the page fault hap, gdtr_base at start is 0x%x gs: 0x%x' % (gdtr_base, gs))
    page_hap = SIM_hap_add_callback_obj_index("Core_Exception", cpu, 0, page_fault_callback, cpu, 14)
    SIM_run_command('pregs -all')

 
    #SIM_continue(num_instructs)
def doWhiteList(cpu):
    address = 0xfd70405c
    cpu.outside_memory_whitelist.append([address, 0x3ff])
    address = 0xfd74405c
    cpu.outside_memory_whitelist.append([address, 0x3ff])
    address = 0xfd72405c
    cpu.outside_memory_whitelist.append([address, 0x3ff])

def page_fault_callback(cpu, one, exception_number):
    global page_hap
    if page_hap is None:
        return
    reg_num = cpu.iface.int_register.get_number("rip")
    eip = cpu.iface.int_register.read(reg_num)
    reg_num = cpu.iface.int_register.get_number("gs")
    gs = cpu.iface.int_register.read(reg_num)
    gdtr_base = cpu.gdtr_base
    print('page fault at eip 0x%x gdtr_base 0x%x gs: 0x%x' % (eip, gdtr_base, gs))
    SIM_hap_delete_callback_id("Core_Exception", page_hap)
    page_hap = None


 
page_hap = None
cycle_event = None
start_cycle = None
num_instructs = int(os.getenv('num_instructs'))
eip_start = os.getenv('eip_start')
eip = int(eip_start, 16)
print('Will trace %d instructions after address 0x%x ' % (num_instructs, eip))
SIM_run_command('$OS_TYPE="linux64"')
SIM_run_command('$USE_ZSIM="YES"')
#SIM_run_command('add-directory "%script%"')
SIM_run_command('add-directory /mnt/cgcsvn/cgc/trunk/cgc-monitor/simics/simicsScripts')
SIM_run_command('add-directory /mnt/cgcsvn/cgc/trunk/cgc-monitor/simics/simicsScripts/targets/x86-x58-ich10')
SIM_run_command('add-directory /usr/share/pyshared/simicsScripts/')
SIM_run_command('$disk_image = "traceTarget.craff"')
SIM_run_command('$cpu_class="core-i7-single"')
SIM_run_command('run-command-file targets/x86-x58-ich10/cmb1.simics')
outfile='./trace-output.txt'
cmd = 'log-setup -no-console -time-stamp -overwrite logfile = %s' % outfile
SIM_run_command(cmd)
tracer = SIM_run_command('new-tracer')
SIM_run_command('untrace-exception -all')
cpu=SIM_current_processor()
doWhiteList(cpu)
obj = SIM_get_object('thrower')
cell = obj.cell_context
hap = None
break_eip = None
if eip == 0:
    startTrace(cpu, None, None, None)
else:
    print('setting break at 0x%x' % eip)
    break_eip = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, eip, 1, 0)
    hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", startTrace, cpu, break_eip)
    print('set break %d hap %d ' % (break_eip, hap))
    SIM_continue(0)


