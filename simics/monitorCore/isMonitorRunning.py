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
from threading import Lock
class isMonitorRunning():
    '''
    Track whether the monitor is busy working.  Intended for use by
    functions that interact with debugger clients that need to know
    when the monitor has completed an operation.
    ''' 
    def __init__(self, lgr):
        self.is_running = False
        self.my_lock = Lock()
        self.lgr = lgr
        self.lgr.debug('isMonitorRunning, init')

    def isRunning(self):
        retval = False
        status = SIM_simics_is_running()
        if status: 
            #self.lgr.debug('isMonitorRunning, simics is running, value: %r' % status)
            retval = True
        else: 
            self.my_lock.acquire()
            retval = self.is_running
            #self.lgr.debug('isMonitorRunning, is monitor running flag set? %r' % retval)
            self.my_lock.release()
        return retval 

    def setRunning(self, is_running):
        #self.lgr.debug('isMonitorRunning set %r' % is_running)
        #self.lgr.debug('isMonitorRunning, get lock')
        self.my_lock.acquire()
        #self.lgr.debug('isMonitorRunning, GOT THE lock')
        self.is_running = is_running
        self.my_lock.release()
        
