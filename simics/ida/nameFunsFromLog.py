import idautils
import ida_bytes
import idaversion
'''
For each function, look for a reference to string containing ": START".  When found
assume that is a log message artifact containing the name of the function.  Use that
to rename the function so it matches the original C.  Intended for stripped files.
'''    
def get_string(ea):
    string_type = idc.get_str_type(idaapi.get_item_head(ea))

    if string_type is None:
        return None

    string = idc.get_strlit_contents(ea, strtype=string_type)

    return string.decode()

def findFunName(s):
    retval = None 
    if s is not None and ': START' in s:
        retval = s.split(':')[0].strip()
    elif s is not None and '::' in s:
        parts = s.split()
        for p in parts:
            if '::' in p:
                if p.endswith('()'):
                    sig = p[:-2]
                elif p.endswith('.') or p.endswith(':'):
                    sig = p[:-1]
                else:
                    sig = p
                if '(' in sig:
                    sig = sig.split('(')[0]
                if sig.startswith('<'):
                    sig = sig[1:-1]
                retval = sig
    return retval
ea = get_screen_ea()
start = idaversion.get_segm_attr(ea, idc.SEGATTR_START)
end = idaversion.get_segm_attr(ea, idc.SEGATTR_END)
for function_ea in idautils.Functions(start,  end):
    fun_name = idaversion.get_func_name(function_ea)
    end = idc.get_func_attr(function_ea, idc.FUNCATTR_END)-1
    done = False
    for head in Heads(function_ea, end):
        refs = DataRefsFrom(head)
        for r in refs:
            s = get_string(r)
            name = findFunName(s)
            if name is not None:
                print(name)
                idaapi.set_name(function_ea, name, idaapi.SN_FORCE)
                done = True
                break
        if done:
            break
                
