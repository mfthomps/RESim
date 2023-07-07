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
mem_prefixes = ['.__', '___', '__', '._', '_', '.', 'isoc99_', 'j_']
def adjustFunName(frame, fun_mgr, lgr): 
        fun = None
        if frame.fun_name is not None:
            fun = frame.fun_name.strip()
            #lgr.debug('dataWatch adjustFunName fun starts as %s' % fun)
            if '@' in frame.fun_name:
                fun = frame.fun_name.split('@')[0]
                try:
                    fun_hex = int(fun, 16) 
                    if fun_mgr is not None:
                        fun_name = fun_mgr.getName(fun_hex)
                        #lgr.debug('looked for fun for 0x%x got %s' % (fun_hex, fun_name))
                        if fun_name is not None:
                            fun = fun_name
                    else:
                        lgr.debug('No ida_funs')
                except ValueError:
                    pass
            for pre in mem_prefixes:
                if fun.startswith(pre):
                    fun = fun[len(pre):]
                    #lgr.debug('found memsomething prefix %s, fun now %s' % (pre, fun))
            if fun.startswith('std::string::'):
                fun = fun[len('std::string::'):]
                if '(' in fun:
                    ''' TBD generalize/test for ghidra? '''
                    fun, param1 = fun.split('(',1)
                    if fun == 'string': 
                        if param1.startswith('char const*'):
                            fun = 'string_chr'
                        elif param1.startswith('std::string'):
                            fun = 'string_std'
                        else:
                            lgr.error('unknown string constructor %s' % fun)
                    elif fun == 'replace': 
                        if 'char' in param1:
                            fun = 'replace_chr'
                        else:
                            fun = 'replace_std'
                    elif fun == 'append': 
                        if 'char' in param1 and 'uint' in param1:
                            fun = 'append_chr_n'
                        elif 'char' in param1:
                            fun = 'append_chr'
                        elif 'std::string' in param1:
                            fun = 'append_std'
                        else:
                            lgr.warning('TBD build out c++ append')
                    elif fun == 'assign': 
                        if 'char' in param1:
                            fun = 'assign_chr'
                    elif fun == 'compare': 
                        if 'char' in param1:
                            fun = 'compare_chr'

            elif fun.startswith('std::__cxx11::'):
                fun = fun[len('std::__cxx11::'):]
                if '(' in fun:
                    ''' TBD generalize/test for ghidra? '''
                    fun, params = fun.split('(',1)
                    if '::' in fun:
                        fun = fun.split('::')[-1]
                    ''' TBD fix this, generalize'''
                    #if 'basic_string' in fun and not params.startswith('void'):
                    if 'basic_string' in fun and params.startswith('char const*,uint'):
                        ''' TBD generalize '''
                        #lgr.debug('clibFuns string function is basic char fun %s params (%s' % (fun, params))
                        fun = 'string_basic_char' 
                    elif 'basic_string' in fun and params.startswith('std::'):
                        #lgr.debug('clibFuns string function is basic std %s params (%s' % (fun, params))
                        fun = 'string_basic_std' 
                  
                    else:
                        lgr.debug('clibFuns string function did not recognize fun %s params (%s' % (fun, params))
                else:
                    lgr.error('clibFuns string function parsing, Expected "(" in %s' % fun)


            ''' TBD clean up this hack?'''
            if fun.endswith('destroy'):
                #lgr.debug('is destroy')
                fun = 'destroy'
            elif fun.startswith('operator new'):
                ''' TBD, happens in unwind code segments, just look for unwind instead?'''
                #lgr.debug('is new')
                fun = 'new'
            elif fun.startswith('operator delete'):
                #lgr.debug('is destroy')
                fun = 'delete'
            elif 'find_first' in fun: 
                fun = 'find_first'
            elif fun.endswith('end_cleanup'):
                fun = 'end_cleanup'
            elif 'replace_safe' in fun:
                fun = 'replace_safe'

            if '__' in fun:
                ''' TBD generalized? '''
                fun = fun.split('__')[1]
            if '<' in fun:
                fun = fun.split('<')[0]
        else:
            lgr.debug('clibFuns fun name was none')
        return fun
   
def allClib(frames, start):
        retval = True
        for i in range(start, -1, -1):
            frame = frames[i]
            if '/libc.so' not in frame.fname:
                retval = False
                break
        return retval
         
class CLibFuns():
    def __init__(self):
        pass
