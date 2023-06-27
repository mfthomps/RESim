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
   Manage instances of the Syscall modules in different contexts.
'''
import syscall
import winSyscall
class SyscallInstance():
    ''' Track Syscall module instances '''
    def __init__(self, name, call_names, syscall, call_param_name, lgr):
        ''' most recently assigned name, do not read too much into it'''
        self.name = name
        ''' the list of syscall names handled by the syscall instance '''
        self.call_names = call_names
        ''' the syscall instance '''
        self.syscall = syscall
        self.param_call_list = {}
        self.param_call_list[call_param_name] = call_names
        self.lgr = lgr

    def toString(self):
        retval = 'Name: %s  calls: %s' % (self.name, str(self.call_names))
        return retval

    def hasCall(self, name):
        if name in self.call_names:
            return True
        else:
            return False

    def callsMatch(self, call_list):
        retval = True
        if len(call_list) == len(self.call_names):
            for call in call_list:
                if call not in self.call_names:
                    retval = False
                    break
        else:
            retval = False
        return retval

    def hasParamName(self, param_name):
        retval = self.syscall.hasCallParam(param_name)
        return retval

    def stopTrace(self, immediate=False):
        self.syscall.stopTrace(immediate=immediate)

    def addCallParams(self, call_params, call_names):
        call_param_name = call_params[0].name
        if call_param_name in self.param_call_list:
            self.lgr.error('syscallManager SyscallInstance addCallParams, %s already in list' % call_param_name)
        else:
            self.param_call_list[call_param_name] = call_names
            self.lgr.debug('syscallManager SyscallInstance addCallParams set call_param_name to %s' % call_names)

    def hasOtherCalls(self, call_param_name):
        retval = []
        for param_name in self.param_call_list:
            if param_name == call_param_name:
                continue
            for call in self.param_call_list[param_name]:
                if call_param_name not in self.param_call_list or call not in self.param_call_list[call_param_name]:
                    if call not in retval:
                        retval.append(call)
        return retval

class SyscallManager():
    def __init__(self, top, cpu, cell_name, param, mem_utils, task_utils, context_manager, traceProcs, sharedSyscall, lgr, 
                   traceMgr, soMap, compat32, targetFS, os_type):
        self.top = top
        self.param = param
        self.cpu = cpu
        self.cell_name = cell_name
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        ''' TBD maybe traceProcs passed in for each instance if it is to be traced? or other mechanism '''
        self.traceProcs = traceProcs
        self.sharedSyscall = sharedSyscall
        self.lgr = lgr
        self.traceMgr = traceMgr
        self.soMap = soMap
        if self.soMap is None:
            self.lgr.error('SOMap is none in syscall manager')
        self.targetFS = targetFS
        self.compat32 = compat32
        self.os_type = os_type

        self.syscall_dict = {}
        self.trace_all = {}

    def watchAllSyscalls(self, context, name, linger=False, background=False, flist=None, callback=None, compat32=None, stop_on_call=False, 
                         trace=False, binders=None, connectors=None, record_fd=False, swapper_ok=False, netInfo=None):
   
        if compat32 is None:
            compat32 = self.compat32

        if context is None:
            context = self.getDebugContextName()
            
        cell = self.context_manager.getCellFromContext(context)
        self.lgr.debug('syscallManager watchAllSyscalls name %s context %s' % (name, context))
        # TBD gather parameters first and stuff them into traceall
        self.rmSyscallByContext(context)
        if self.top.isWindows(self.cell_name):
            retval = winSyscall.WinSyscall(self.top, self.cell_name, cell, self.param, self.mem_utils, 
                               self.task_utils, self.context_manager, self.traceProcs, self.sharedSyscall, 
                               self.lgr, self.traceMgr, call_list=None, call_params=[], targetFS=self.targetFS, linger=linger, 
                               background=background, name=name, flist_in=flist, callback=callback, 
                               stop_on_call=stop_on_call, trace=trace, soMap=self.soMap,
                               record_fd=record_fd, swapper_ok=swapper_ok)
        else:
            retval = syscall.Syscall(self.top, self.cell_name, cell, self.param, self.mem_utils, 
                               self.task_utils, self.context_manager, self.traceProcs, self.sharedSyscall, 
                               self.lgr, self.traceMgr, call_list=None, call_params=[], targetFS=self.targetFS, linger=linger, 
                               background=background, name=name, flist_in=flist, callback=callback, compat32=compat32, 
                               stop_on_call=stop_on_call, trace=trace, binders=binders, connectors=connectors, 
                               netInfo=netInfo, record_fd=record_fd, swapper_ok=swapper_ok)
        self.trace_all[context] = retval
        return retval

    def getDebugContextName(self):
        ''' return the debugging context if debugging.  Otherwise return default context '''
        debug_pid, debug_cpu = self.context_manager.getDebugPid()
        if debug_pid is not None:
            context = self.context_manager.getRESimContextName()
        else:
            context = self.context_manager.getDefaultContextName()
        return context 

    def watchSyscall(self, context, call_list, call_params_list, name, linger=False, background=False, flist=None, 
                     callback=None, compat32=False, stop_on_call=False, skip_and_mail=True, kbuffer=None):
        ''' Create a syscall instance.  Intended for use by other modules, not by this module.
            Assumes all of the call_params have the same call parameter name for purposes of managing the
            call instances, e.g, an open watched for a dmod and a SO mapping.
        '''
        self.lgr.debug('watchSyscall')
        retval = None 
        if context is None:
            context = self.getDebugContextName()

        cell = self.context_manager.getCellFromContext(context)

        if len(call_params_list) == 0:
            ''' For use in deleting syscall instances '''
            dumb_param = syscall.CallParams(name, None, None)
            call_params_list.append(dumb_param)
            self.lgr.debug('syscallManager watchSyscall context %s, added dummy parameter with name %s' % (context, name))

        call_instance = self.findCalls(call_list, context)
        if call_instance is None:
            if self.top.isWindows(self.cell_name):
                retval = winSyscall.WinSyscall(self.top, self.cell_name, cell, self.param, self.mem_utils, 
                               self.task_utils, self.context_manager, self.traceProcs, self.sharedSyscall, self.lgr, self.traceMgr,
                               call_list=call_list, call_params=call_params_list, targetFS=self.targetFS, linger=linger, 
                               background=background, name=name, flist_in=flist, callback=callback, soMap=self.soMap, 
                               stop_on_call=stop_on_call, skip_and_mail=skip_and_mail, kbuffer=kbuffer)
            else:
                retval = syscall.Syscall(self.top, self.cell_name, cell, self.param, self.mem_utils, 
                               self.task_utils, self.context_manager, self.traceProcs, self.sharedSyscall, self.lgr, self.traceMgr,
                               call_list=call_list, call_params=call_params_list, targetFS=self.targetFS, linger=linger, 
                               background=background, name=name, flist_in=flist, callback=callback, compat32=compat32, 
                               stop_on_call=stop_on_call, skip_and_mail=skip_and_mail, kbuffer=kbuffer)
            ''' will have at least one call parameter, perhaps the dummy. '''
            call_param_name = call_params_list[0].name
            self.lgr.debug('syscallManager watchSyscall context %s, created new instance for %s, call_param_name: %s' % (context, name, call_param_name))
            call_instance = SyscallInstance(name, call_list, retval, call_param_name, self.lgr)
            if context not in self.syscall_dict:
                self.syscall_dict[context] = {}
            self.syscall_dict[context][name] = call_instance
        else:
            if call_instance.callsMatch(call_list):
                call_instance.addCallParams(call_params_list, call_list)
                self.lgr.debug('syscallManager watchSyscall, did not create new instance for %s, added params to %s' % (name, call_instance.name))
                retval = call_instance.syscall
            else:
                self.lgr.debug('syscallManager watchSyscall given call list is superset of existing calls.  Delete and recreate')
                existing_call_params = call_instance.syscall.getCallParams()
                for cp in call_params_list:
                    existing_call_params.append(cp)
                if kbuffer is None:
                    kbuffer = call_instance.syscall.kbuffer
                if callback is not None and call_instance.syscall.callback is not None and callback != call_instance.syscall.callback:
                    self.lgr.error('syscallManager watchSyscall conflicting callbacks')
                if callback is None:
                    callback = call_instance.syscall.callback
                call_instance.syscall.stopTrace()
                ''' TBD what about flist and stop action?'''
                if self.top.isWindows(self.cell_name):
                    retval = winSyscall.WinSyscall(self.top, self.cell_name, cell, self.param, self.mem_utils, 
                               self.task_utils, self.context_manager, self.traceProcs, self.sharedSyscall, self.lgr, self.traceMgr,
                               call_list=call_list, call_params=existing_call_params, targetFS=self.targetFS, linger=linger, 
                               background=background, name=name, flist_in=flist, callback=callback, stop_on_call=stop_on_call, kbuffer=kbuffer)
                else:
                    retval = syscall.Syscall(self.top, self.cell_name, cell, self.param, self.mem_utils, 
                               self.task_utils, self.context_manager, self.traceProcs, self.sharedSyscall, self.lgr, self.traceMgr,
                               call_list=call_list, call_params=existing_call_params, targetFS=self.targetFS, linger=linger, 
                               background=background, name=name, flist_in=flist, callback=callback, compat32=compat32, stop_on_call=stop_on_call, kbuffer=kbuffer)
                call_instance.syscall = retval
                call_instance.addCallParams(call_params_list, call_list)

 
        return retval

    def rmSyscall(self, call_param_name, immediate=False, context=None, rm_all=False):
        ''' Find and remove the syscall having the given call parameters name (unless it has additional call params,
            in which case just removed the named params).
            If the syscall instance has additional calls, remove the instance and recreate it having only 
            the other calls.
        '''
        if context is None:
            context = self.getDebugContextName()
        call_instance = self.findInstanceByParams(call_param_name, context)
        if call_instance is None:
            self.lgr.debug('syscallManager rmSyscall did not find syscall instance with context %s and param name %s' % (context, call_param_name))
        else:
            self.lgr.debug('syscallManager rmSyscall call_param_name %s' % call_param_name)
            remaining_params = call_instance.syscall.rmCallParamName(call_param_name)       
            other_calls = call_instance.hasOtherCalls(call_param_name)
            if rm_all or len(other_calls) == 0:
                if len(remaining_params) == 0:
                    call_instance.stopTrace(immediate=immediate) 
                    del self.syscall_dict[context][call_instance.name]
                    self.lgr.debug('syscallManager rmSyscall context %s.  Removed call params %s, nothing left, remove syscall instance' % (context, call_param_name))
                else:
                    self.lgr.debug('syscallManager rmSyscall context %s.  Removed call params %s, syscall remains, must be other params' % (context, call_param_name))
            else:
                ''' Other syscalls.  Delete and recreate with other syscalls. '''
                self.lgr.debug('syscallManager rmSyscall call to stopTrace will stop and delete syscall instance %s (%s) other_calls is %s' % (call_instance.name, 
                    call_instance.syscall.name, str(other_calls)))
                call_instance.stopTrace(immediate=immediate) 
                del self.syscall_dict[context][call_instance.name]
                ''' TBD what about the flist? '''
                if self.top.isWindows(self.cell_name):
                    compat32 = False
                else:
                    compat32 = call_instance.syscall.compat32
                new_call_instance = self.watchSyscall(context, other_calls, remaining_params, call_instance.name, compat32=compat32) 

                call_instance = SyscallInstance(call_instance.name, other_calls, new_call_instance, call_instance.name, self.lgr)

                self.syscall_dict[context][call_instance.name] = call_instance
                self.lgr.debug('syscallManager rmSyscall context %s removed %s and recreated instance' % (context, call_instance.name))

    def findInstanceByParams(self, call_param_name, context):
        ''' Return the Syscallinstance that contains params having the given name.   Assumes only one. '''
       
        retval = None
        if context in self.syscall_dict:
            for instance_name in self.syscall_dict[context]:
                call_instance = self.syscall_dict[context][instance_name]
                if call_instance.hasParamName(call_param_name):
                    retval = call_instance
                    break
        return retval 

    def findCalls(self, call_list, context):
        ''' Return the Syscallinstance that contains at least one call in the given call list if any.
            Does not look for multiple instances with same call.  TBD?
        '''
       
        retval = None
        if context in self.syscall_dict:
            for instance_name in self.syscall_dict[context]:
                call_instance = self.syscall_dict[context][instance_name]
                for call in call_list:
                    if call_instance.hasCall(call):
                        retval = call_instance
                        break
        return retval 

    def rmAllSyscalls(self):
        self.lgr.debug('syscallManager rmAllSyscalls')
        retval = False
        rm_list = {}
        for context in self.syscall_dict:
            rm_list[context] = []
            for instance_name in self.syscall_dict[context]:
                rm_list[context].append(instance_name)
                self.syscall_dict[context][instance_name].stopTrace()
                self.lgr.debug('syscallManager rmAllSyscalls remove %s' % instance_name)
                retval = True
        for context in rm_list:
            for instance_name in rm_list[context]:
                del self.syscall_dict[context][instance_name]
            del self.syscall_dict[context]

        rm_context = []
        for context in self.trace_all:
            self.lgr.debug('syscallManager rmAllSyscalls remove trace_all for context %s' % context)
            self.trace_all[context].stopTrace()
            rm_context.append(context)
            retval = True
        for context in rm_context:
            del self.trace_all[context]
        return retval
        
    def rmSyscallByContext(self, context):
        self.lgr.debug('syscallManager rmSyscallByContext')
        retval = False
        rm_list = []
        if context in self.syscall_dict:
            for instance_name in self.syscall_dict[context]:
                rm_list.append(instance_name)
                self.syscall_dict[context][instance_name].stopTrace()
                self.lgr.debug('syscallManager mrSyscallByContext remove %s' % instance_name)
                retval = True

            for instance_name in rm_list:
                del self.syscall_dict[context][instance_name]
            del self.syscall_dict[context]

        if context in self.trace_all:
            self.lgr.debug('syscallManager mrSyscallByContext remove trace_all for context %s' % context)
            self.trace_all[context].stopTrace()
            retval = True
            del self.trace_all[context]
        return retval

    #def stopTrace(self, param_name):

    def stopTracexx(self, syscall):
        ''' TBD not done'''
        dup_traces = self.call_traces[cell_name].copy()
        for call in dup_traces:
            syscall_trace = dup_traces[call]
            if syscall is None or syscall_trace == syscall: 
                #self.lgr.debug('genMonitor stopTrace cell %s of call %s' % (cell_name, call))
                syscall_trace.stopTrace(immediate=True)
                #self.lgr.debug('genMonitor back from stopTrace')
                self.rmCallTrace(cell_name, call)

        if cell_name in self.trace_all and (syscall is None or self.trace_all[cell_name]==syscall):
            self.lgr.debug('call stopTrace for trace_all')
            self.trace_all[cell_name].stopTrace(immediate=False)
            del self.trace_all[cell_name]

            for exit in self.exit_maze:
                exit.rmAllBreaks()
        if cell_name not in self.trace_all and len(self.call_traces[cell_name]) == 0:
            self.traceMgr[cell_name].close()

        #if self.instruct_trace is not None:
        #    self.stopInstructTrace()

    def remainingCallTraces(self, exception=None, context=None):
        ''' Are there any call traces remaining, if so return True
            unless the only remaining trace is named by the given exception '''
            
        retval = False
        if context is None:
            context = self.getDebugContextName()
        if exception is None:
            if context in self.syscall_dict and len(self.syscall_dict[context])>0:
                retval = True 
        else:
            if context in self.syscall_dict:
                if len(self.syscall_dict[context]) == 1:
                    instance = self.findCalls([exception], context)
                    if instance is None:
                        ''' only one, but not the exception '''
                        retval = True
                elif len(self.syscall_dict[context]) > 1:
                        retval = True
                   
        return retval 

    def showSyscalls(self):
        for context in self.syscall_dict:
            print('\tcontext: %s' % context)
            for instance in self.syscall_dict[context]:
                out_string = self.syscall_dict[context][instance].toString()
                print('\t\t%s' % out_string)
