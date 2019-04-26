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

'''
gota be a better way. but it works.
Watch the simulated machine until a sshd process has been created, then complete.
Intended to delay execution of the real monitor code until a kernel is in place.

'''
from simics import *
import sys
import os
import time
DEVEL = os.getenv('CGC_DEVEL')
SIMICS_VER = os.getenv('SIMICS_VER')
import bsdParams
import bsd64Params
import linux64Params
import osUtils

#SIM_SCRIPTS = '/mnt/cgc/simics/simicsScripts'
PY_SHARED = '/usr/share/pyshared'
if DEVEL is not None and (DEVEL == 'YES'):
    print 'USING DEVELOPMENT PATHS'
    #SIM_SCRIPTS = '/mnt/cgcsvn/cgc/users/mft/simics/simicsScripts'
    #ZK_PY= '/mnt/cgcsvn/cgc/users/mft/zk/py'
else:
   print 'USING TARGET PATHS'

if PY_SHARED not in sys.path:
    sys.path.append(PY_SHARED)
CORE = os.path.join(PY_SHARED, 'monitorCore')
if CORE not in sys.path:
    sys.path.append(CORE)
from monitorCore import *
from monitorLibs import configMgr
#default to target on Simics 4.6
lib = "/mnt/cgc/simics/install/simics-4.6.84/linux64/lib/"
if SIMICS_VER is not None and SIMICS_VER == '4.8':
    lib = configMgr.sim_lib_path
    print "USING 4.8 PATHS"
elif DEVEL is not None and DEVEL == 'YES':
    print("************USING 4.6**********")
    lib = "/home/mike/simics-4.6/simics-4.6.84/linux64/lib/"

if lib not in sys.path:
    sys.path.append(lib)


#if SIM_SCRIPTS not in sys.path:
#    sys.path.append(SIM_SCRIPTS)
import logging
import kernelInfo
import osUtils
import memUtils
import cellConfig
import linuxProcessUtils
import bsdProcessUtils
from monitorLibs import utils
class delayUntilBoot():
    def __init__(self, OS_TYPE, ONE_BOX):
        num_boxes = 3
        if ONE_BOX == 'YES':
            num_boxes = 1
        self.__cell_config = cellConfig.cellConfig(num_boxes, OS_TYPE)
        self.__cell_config.loadCellObjects()
        cfg = configMgr.configMgr(self.__cell_config.os_type)
        self.__os_params = osUtils.getOSParams(self.__cell_config.os_type)
        self.lgr = logging.getLogger(__name__)
        print('log to tmp')
        fh = logging.FileHandler('/tmp/delayUntilBoot.log')
        fh.setLevel(logging.DEBUG)
        frmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(frmt)
        self.lgr.addHandler(fh)
        self.param = {}
        self.__mem_utils = {}
        self.__kernel_info = {}
        self.os_utils = {}
        for cell_name in self.__cell_config.os_type:
            if self.__cell_config.os_type[cell_name] == osUtils.LINUX:
                settings, p_file = osUtils.loadParameters(os.path.join(cfg.os_params_dir, self.__os_params[cell_name]))
                self.param[cell_name] = linuxParams.linuxParams()
                self.__mem_utils[cell_name] = memUtils.memUtils(4, self.param[cell_name])
            elif self.__cell_config.os_type[cell_name] == osUtils.LINUX64:
                self.param[cell_name] = linux64Params.linux64Params()
                self.__mem_utils[cell_name] = memUtils.memUtils(8, self.param[cell_name])
            elif self.__cell_config.os_type[cell_name] == osUtils.FREE_BSD64:
                self.param[cell_name] = bsd64Params.bsd64Params()
                self.__mem_utils[cell_name] = memUtils.memUtils(8, self.param[cell_name])
            else:
                self.param[cell_name] = bsdParams.bsdParams()
                self.__mem_utils[cell_name] = memUtils.memUtils(4, self.param[cell_name])
            self.__kernel_info[cell_name] = kernelInfo.kernelInfo(self.lgr, self.__cell_config.os_type[cell_name], 
                                     self.param[cell_name], cfg.system_map[cell_name], cfg.cgc_bytes) 
            self.lgr.debug('*********in delay until boot, map file %s, current_task is %x' % (cfg.system_map[cell_name], 
                 self.__kernel_info[cell_name].current_task))
            print('*********in delay until boot, map file %s, current_task is %x' % (cfg.system_map[cell_name], 
                 self.__kernel_info[cell_name].current_task))
            if self.__cell_config.os_type[cell_name] == 'linux':
                self.os_utils[cell_name] = linuxProcessUtils.linuxProcessUtils(self, cell_name, self.param[cell_name], 
                    self.__cell_config, None, None, self.__kernel_info[cell_name].current_task, 
                    self.__mem_utils[cell_name], self.lgr, False)
            elif self.__cell_config.os_type[cell_name] == 'linux64':
                self.os_utils[cell_name] = linuxProcessUtils.linuxProcessUtils(self, cell_name, self.param[cell_name], 
                    self.__cell_config, None, None, self.__kernel_info[cell_name].current_task, 
                    self.__mem_utils[cell_name], self.lgr, False)
            else:
                self.os_utils[cell_name] = bsdProcessUtils.bsdProcessUtils(self, cell_name, self.param[cell_name], 
                    self.__cell_config, None, None, None, 
                    self.__mem_utils[cell_name], self.lgr)

        self.code_break_num = None
        self.changed_hap = None
        self.all_done = False

    def getTopComponentName(self, cpu):
         names = cpu.name.split('.')
         return names[0]

    def getGSCurrent_task_offset(self, cpu):
        gs_base = cpu.ia32_gs_base
        #retval = gs_base+0xb700
        cell_name = self.getTopComponentName(cpu)
        retval = gs_base + self.param[cell_name].cur_task_offset_into_gs
        print('delayUntilBoot gs base is 0x%x, plus current_task offset is 0x%x' % (gs_base, retval))
        return retval


    ''' TBD hueristic tries to wait until it appears the kernel has a good task address '''
    def getTaskAddr(self, cpu):
        done = False
        cell_name = self.getTopComponentName(cpu)
        if self.__cell_config.os_type[cell_name].startswith(osUtils.FREE_BSD):
            while not done:
                retval = self.os_utils[cell_name].getPhysAddrOfCurrentThread(cpu)
                if retval != 0x40000000:
                    done = True
                else:
	            SIM_continue(9000000000)
        elif self.__cell_config.os_type[cell_name] == osUtils.LINUX64:
            cmd = '%s.get-processor-list' % cell_name
            proclist = SIM_run_command(cmd)
            while not done:
                while SIM_processor_privilege_level(cpu) != 0:
                    print('not in pl0, fiddle some')
	            SIM_continue(100000000)
                gs_b700 = self.getGSCurrent_task_offset(cpu)
                current_addr = self.__mem_utils[cell_name].readPtr(cpu, gs_b700)
                current_addr = self.__mem_utils[cell_name].getUnsigned(current_addr)
                print 'delayUntilBoot getTaskAddr current_addr is 0x%x compare to base of 0x%x' % (current_addr, self.param[cell_name].kernel_base)
                if current_addr < self.param[cell_name].kernel_base:
                    print 'not a good address, try another'
    		    SIM_continue(9000000000)
                else:
                    cmd = 'logical-to-physical %s fs:0x%x' % (proclist[0], current_addr)
                    print 'cmd is %s' % cmd
                    retval = SIM_run_command(cmd)
                    print 'delayUntilBoot getTaskAddr phys of current task is %x' % retval
                    if retval != 0 and retval != 0xffffffffffffffff:
                        done = True
                    else:
        	        SIM_continue(9000000000)
            print 'got good task addr %x' % retval
            self.os_utils[cell_name].setCurrentTask(cpu) 


        else:
            k_physical = self.__kernel_info[cell_name].current_task - 0xc0000000        
            cell_name = self.getTopComponentName(cpu)
            cmd = '%s.get-processor-list' % cell_name
            proclist = SIM_run_command(cmd)
            while not done:
                while SIM_processor_privilege_level(cpu) != 0:
                    print('not in pl0, fiddle some')
	            SIM_continue(100000000)
                cmd = 'logical-to-physical %s fs:0x%x' % (proclist[0], self.__kernel_info[cell_name].current_task)
                print 'cmd is %s' % cmd
                retval = SIM_run_command(cmd)
                print 'delayUntilBoot getTaskAddr current task is %x' % retval
                if retval != self.__kernel_info[cell_name].current_task and retval != k_physical and retval < 0xffffffff:
                    done = True
                else:
    		    SIM_continue(9000000000)
            print 'got good task addr %x' % retval
            reg_num = cpu.iface.int_register.get_number("cr3")
            cr3 = cpu.iface.int_register.read(reg_num)
            self.os_utils[cell_name].setCurrentTask(cpu) 
            print('***************************************************got cr3 value of 0x%x' % cr3)
            
        return retval

    def doDelay(self, cpu, comm):
        cell_name = self.getTopComponentName(cpu)
        done = False
        real_trigger = 5
        count = 0
        tasks = []
        print('in doDelay')
        while not done:
            SIM_continue(9000000000)
            if self.__cell_config.os_type[cell_name].startswith(osUtils.FREE_BSD):
                # hackrey, assume if one core has settled, all others have
                ct = self.os_utils[cell_name].getPhysAddrOfCurrentThread(cpu)
                if ct != 0 and ct != 0x40000000:
                    tasks = self.os_utils[cell_name].getProcList()
                    for task in tasks:
                        if task.comm == comm:
                            print 'got %s on %s' % (comm, cell_name)
                            done = True
            else:
                tasks = self.os_utils[cell_name].getTaskStructs()
                print('called getTaskStructs with num tasks is %d' % (len(tasks)))
              
                for task in tasks:
                   if tasks[task].comm == comm:
                        print 'got %s' % comm
                        done = True
                count += 1
                if count > 20:
                    return 0
        return 0

    def waitUntilGone(self, cpu, comm):
        cell_name = self.getTopComponentName(cpu)
        done = False
        real_trigger = 5
        count = 0
        tasks = []
        print('in doDelay')
        while not done:
            SIM_continue(9000000000)
            if self.__cell_config.os_type[cell_name].startswith(osUtils.FREE_BSD):
                # hackrey, assume if one core has settled, all others have
                ct = self.os_utils[cell_name].getPhysAddrOfCurrentThread(cpu)
                if ct != 0 and ct != 0x40000000:
                    tasks = self.os_utils[cell_name].getProcList()
                    done = True
                    for task in tasks:
                        if task.comm == comm:
                            print 'got %s' % comm
                            done = False
            else:
                tasks = self.os_utils[cell_name].getTaskStructs()
                print('called getTaskStructs with num tasks is %d' % (len(tasks)))
                done = True 
                for task in tasks:
                   if tasks[task].comm == comm:
                        print 'got %s' % comm
                        done = False
                count += 1
                if count > 20:
                    return 0
        return 0
        #logging.disable(logging.DEBUG)
if __name__ == "__main__":
    lb = delayUntilBoot()
    lb.doDelay()
