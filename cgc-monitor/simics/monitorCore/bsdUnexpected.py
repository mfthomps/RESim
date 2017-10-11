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

import getSymbol
import osUtils
class bsdUnexpected():
    '''
    Identity code regions that should not be executed when a monitored process is
    scheduled.  Use symbols from a sorted kernel map, and permit holes within symbol 
    ranges.
    '''
    def __init__(self, map_file, os_type, lgr):
        self.region_symbols = []
        self.regions = []
        self.lgr = lgr
        lgr.debug('bsdUnexpected map_file is %s os_type is %s' % (map_file, os_type))
        if os_type == osUtils.FREE_BSD:
            lgr.debug('bsdUnexpected doing bsd regions')
            self.region_symbols.append(self.regionSymbol('sys_execve', 'sysctl_kern_stackprot'))
            self.region_symbols.append(self.regionSymbol('sys_fork', 'sysctl_kern_randompid'))
            self.region_symbols.append(self.regionSymbol('device_probe', 'resource_list_init'))
        elif os_type == osUtils.FREE_BSD64:
            lgr.debug('bsdUnexpected doing bsd64 regions')
            self.region_symbols.append(self.regionSymbol('sys_execve', 'sysctl_kern_stackprot'))
            self.region_symbols.append(self.regionSymbol('sys_fork', 'sysctl_kern_randompid'))
            self.region_symbols.append(self.regionSymbol('device_probe', 'resource_list_init'))
        elif os_type == osUtils.LINUX:
            lgr.debug('bsdUnexpected doing linux regions')
            holes = []
            holes.append(self.getRegionFromMap(map_file, '__get_dumpable', 'sys_execve'))
            lgr.debug('back from getRegionFromMap map_file %s' % map_file)
            self.region_symbols.append(self.regionSymbol('do_execve', 'generic_pipe_buf_confirm', holes))
            self.region_symbols.append(self.regionSymbol('fork_idle', 'no_blink'))
            self.region_symbols.append(self.regionSymbol('device_add_groups', 'drv_attr_show'))
        elif os_type == osUtils.LINUX64:
            self.region_symbols.append(self.regionSymbol('check_unsafe_exec', 'setup_new_exec'))
        for r in self.region_symbols:
            r = self.getRegionFromMap(map_file, r.start, r.end, r.holes)
            self.regions.append(r)

    def getRegionFromMap(self, map_file, start_sym, end_sym, holes=None):
        start = getSymbol.getSymbol(map_file, start_sym, True)
        end = getSymbol.getSymbol(map_file, end_sym, True)
        if start is None or end is None:
            self.lgr.error('unable to find symbols %s or %s in %s' % (start_sym, end_sym, map_file))
            return None
        length = end - start
        return self.region(start, length, holes)

    def getRegions(self):
        return self.regions

    class regionSymbol:
        def __init__(self, start, end, holes=None):
            self.start = start
            self.end = end
            self.holes = holes
            
    class region:
        def __init__(self, start, length, holes=None):
            self.start = start
            self.length = length
            self.holes = holes

