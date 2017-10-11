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

import cellInfo
import simics
from simics import *
import osUtils
import os
#TBD replace with config file
# TBD fix this to be either CB or POV
class cellConfig():
    cells = {}
    cell_context = {}
    cell_cpu = {}
    cell_cpu_list = {}
    cell_cgc_address = {}
    ip_address = {}
    ssh_port = {}
    os_type = {}
    def __init__(self, num_boxes=3, os_config=osUtils.MIXED_LLK):
        print('Cell config using 4.8, num_boxes is %d os type: %s' % (num_boxes, os_config))
        first_box = 'thrower' 
        second_box = 'ids' 
        third_box = 'server' 
        self.cells[first_box] = 'pov thrower'
        self.ip_address[first_box] = '10.10.0.100'
        self.ssh_port[first_box] = 5022
        self.cell_cgc_address[first_box] = None
        # thrower is bsd unless type is linux
        self.os_type[first_box] = osUtils.FREE_BSD
        if os_config == osUtils.LINUX or os_config == osUtils.MIXED_DLD:
            self.os_type[first_box] = osUtils.LINUX
        elif os_config == osUtils.FREE_BSD64 or os_config == osUtils.MIXED_KLK64:
            self.os_type[first_box] = osUtils.FREE_BSD64
        elif os_config == osUtils.LINUX64:
            # just for smoke testing
            self.os_type[first_box] = osUtils.LINUX64
        if num_boxes == 3:
            self.cells[second_box] = 'ids'
            self.cells[third_box] = 'network host'
            self.ip_address[second_box] = '10.10.0.101'
            self.ip_address[third_box] = '10.10.0.102'
            self.ssh_port[second_box] = 6022
            self.ssh_port[third_box] = 7022
            self.cell_cgc_address[second_box] = None
            self.cell_cgc_address[third_box] = None
            # ids is linux64 unless bsd or linux requested
            self.os_type[second_box] = osUtils.LINUX64
            if os_config == osUtils.FREE_BSD:
                self.os_type[second_box] = osUtils.FREE_BSD
            elif os_config == osUtils.LINUX:
                self.os_type[second_box] = osUtils.LINUX
            elif os_config == osUtils.FREE_BSD64:
                self.os_type[second_box] = osUtils.FREE_BSD64
            # defhost is bsd unless linux requested
            self.os_type[third_box] = osUtils.FREE_BSD
            if os_config == osUtils.LINUX or os_config == osUtils.MIXED_DLD:
                self.os_type[third_box] = osUtils.LINUX
            elif os_config == osUtils.FREE_BSD64 or os_config == osUtils.MIXED_KLK64:
                self.os_type[third_box] = osUtils.FREE_BSD64

        elif num_boxes == 2:
            # NOT USED, looks broken
            self.cells[third_box] = 'network host'
            self.ip_address[third_box] = '10.10.0.101'
            self.ssh_port[third_box] = 6022
            self.cell_cgc_address[second_box] = None
        ''' two-box linux '''
        #self.cells['dredd0'] = 'network host'
        #self.cells['dredd1'] = 'pov thrower'
        ''' two-box bsd '''
        #self.cells['tango_0'] = 'pov thrower'
        #self.cells['tango_1'] = 'pov thrower'

        ''' location of CGC code module in BSD.  for linux, TBD handling all the loadable modules '''
        #self.cell_cgc_address['dredd0'] = 0xc36fe000
        #self.cell_cgc_address['dredd1'] = 0xc36fe000
        #self.cell_cgc_address['tango_1'] = 0xc4665000


    def loadCellObjects(self):
        for cell_name in self.cells:
            obj = SIM_get_object(cell_name)
            self.cell_context[cell_name] = obj.cell_context

        for cell_name in self.cells:
            cmd = '%s.get-processor-list' % cell_name
            proclist = SIM_run_command(cmd)
            self.cell_cpu[cell_name] = SIM_get_object(proclist[0])
            self.cell_cpu_list[cell_name] = []
            for proc in proclist:
                self.cell_cpu_list[cell_name].append(SIM_get_object(proc))

    def cpuFromCell(self, cell_name):
        ''' simplification for single-core sims '''
        return self.cell_cpu[cell_name]

    def cpuListFromCell(self, cell_name):
        return self.cell_cpu_list[cell_name]

    def getCBCell(self):
        for cell_name in self.cells:
            if self.cells[cell_name] == 'network host':
                return cell_name
        return None
