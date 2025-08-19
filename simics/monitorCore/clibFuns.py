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
std_prefixes = ['.__', '___', '__', '._', '_', '.', 'isoc99_', 'j_', 'stdio_common_', 'std::']
opc_prefixes = ['UaBase_P_', 'OpcUa_P_String_', 'OpcUa_']
mem_prefixes = std_prefixes + opc_prefixes

def adjustFunName(fun_name, fun_mgr, lgr): 
        fun = None
        if fun_name is not None:
            fun = fun_name.strip()
            #lgr.debug('clibFuns adjustFunName fun starts as %s' % fun)
            if '@' in fun_name:
                fun = fun_name.split('@')[0]
                try:
                    ''' an ida function name reflecting original address (not rebased) '''
                    fun_hex = int(fun, 16) 
                    if fun_mgr is not None:
                        fun_name = fun_mgr.getName(fun_hex)
                        lgr.debug('clibFuns adjustFunName looked for fun for 0x%x got %s from fun_name %s' % (fun_hex, fun_name, fun_name))
                        if fun_name is not None:
                            fun = fun_name
                    else:
                        lgr.debug('No ida_funs')
                except ValueError:
                    pass
            for pre in mem_prefixes:
                if fun.startswith(pre):
                    fun = fun[len(pre):]
                    if pre in opc_prefixes:
                        if fun.endswith('A'):
                            fun = fun[:-1]
                        fun = fun.lower()
                    lgr.debug('clibFuns found memsomething prefix %s, fun now %s' % (pre, fun))
                      
            if fun.startswith('string::'):
                fun = fun[len('string::'):]
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

            elif fun.startswith('basic_istringstream'):
                # TBD will need variations based on templates?
                fun = 'basic_istringstream'
                lgr.debug('clibFuns istring windows fun %s' % fun)
            elif fun.startswith('basic_string'):
                stringbuf=False
                if fun.startswith('basic_stringbuf'):
                    stringbuf = True
                lgr.debug('clibFuns basic_string windows fun %s' % fun)
                if '(' in fun:
                    pre_paren, in_paren = fun.split('(', 1)
                    fun = pre_paren.split('::')[-1]
                    if fun.startswith('allocator'):
                        lgr.debug('clibFuns windows fun %s looks like allocator pre_paren %s in_paran %s' % (fun, pre_paren, in_paren))
                        #if in_paren.startswith('char'):
                        if 'char' in in_paren:
                            lgr.debug('clibFuns windows fun %s looks like allocator for char*' % fun)
                            if stringbuf:
                                fun = 'stringbuf_win_basic_char' 
                            else:
                                fun = 'string_win_basic_char' 
                else:
                    lgr.debug('clibFuns expected parens.  TBD QTCore?')
            elif fun.startswith('basic_streambuf'):
                if 'sgetc' in fun or 'snextc' in fun:
                    fun = 'win_streambuf_getc'
                      
            elif fun.startswith('__cxx11::'):
                fun = fun[len('__cxx11::'):]
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

            elif fun.startswith('crt_stdio_output::'):
                fun = fun[len('crt_stdio_output::'):]
                if '<' in fun:
                    fun = fun.split('<', 1)[0]
            elif fun.startswith('??'):
                # windows TBD remove this since demangle should make it never happen
                if 'basic_string' in fun:
                    lgr.debug('clibFuns basic string fun: %s' % fun)
                    fun = 'string_basic_windows'
                elif fun.startswith('??_'):
                    fun = fun[3:]
            elif fun.startswith('ZN') and 'Q' in fun[:9]:
                #lgr.debug('is QT')
                ''' QTCore5 '''
                fun = fun.split('Q', 1)[1]
                latin = False
                lgr.debug('clibFuns ZN fun is %s' % fun)
                if 'Latin' in fun:
                    lgr.debug('clibFuns has Latin')
                    latin  = True
                q_suffix = ['EP', 'SER', 'ER', 'E5', 'Ev', 'Ei', 'E13']
                for suf in q_suffix:
                    if suf in fun:
                        fun = fun.split(suf)[0]
                        if latin:
                            fun = fun+'_latin'
                            lgr.debug('clibFuns Latin suffix, fun now %s' % fun)
                        break
            elif fun.startswith('Zeq') and 'Q' in fun[:9]:
                fun = fun.split('Q')[1]+'eq'
            elif fun.startswith('Z') and 'QString' in fun and 'Hash' in fun:
                fun = 'QStringHash'
            elif fun.startswith('Z') and 'QString' in fun:
                fun = 'QString'

            ''' TBD clean up this hack?'''
            if fun.endswith('destroy') or 'destructor' in fun:
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
      
            if fun.startswith('_Rep::_'):
                fun = fun[len('_Rep::_'):]
            if '(' in fun:
                fun = fun.split('(')[0]
            
        else:
            #lgr.debug('clibFuns fun name was none')
            pass
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
