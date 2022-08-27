import idautils
from idautils import *
from idc import *
from idaapi import *
import ida_ua
import ida_kernwin

'''
Look for refs to log_stuff or fprintf and then look for refs to what might
be log entries containing function names.  Present the user with dialog to
accept new function names.
'''
def is_function_name(cur_func_name):
    if cur_func_name.startswith("AutoFunc_"):
        return True
    elif cur_func_name.startswith("sub_"):
        return True
    else:
        return False

def get_string(ea):
    string_type = idc.get_str_type(idaapi.get_item_head(ea))

    if string_type is None:
        return None

    string = idc.get_strlit_contents(ea, strtype=string_type)

    return string 

def getFunFromRef(dref):
   retval = None
   log_entry = get_string(dref)
   if log_entry is not None and ':' in log_entry:
       fname = log_entry.split(':',1)[0].strip()
       if fname == 'MON':
           fname = log_entry.split()[1]
           if fname.endswith('()'):
               fname = fname[:-2]
           retval = fname
       elif fname != 'CONFIG' and not fname == 'STATUS' and not fname.startswith('%'):
           if fname.endswith('()'):
               fname = fname[:-2]
           retval = fname
   return retval

for ea in idautils.Functions():
   #if idc.get_func_flags(ea) & (idc.FUNC_LIB | idc.FUNC_THUNK): 
   #    continue
   name = idc.get_func_name(ea)
   did_these = []
   bail = False
   if name == 'log_stuff' or 'fprintf' in name:
       print(hex(ea), idc.get_func_name(ea))
       for ref in CodeRefsTo(ea, 1):
           #print(ref) 
           if True:
               prev = ref
               for i in range(10):
                   prev = idc.prev_head(prev)
                   if True:
                       for dref in DataRefsFrom(prev):
                           #print('prev: 0x%x 0x%x' % (prev, dref))
                           fname = getFunFromRef(dref)
                           if fname is not None and fname not in did_these:
                                   function_start = idc.get_func_attr(prev, idc.FUNCATTR_START)
                                   current_func_name = idc.get_func_name(function_start)
                                   #print('function: %s current is %s' % (fname, current_func_name))
                                   if is_function_name(current_func_name):
                                       prompt = ('replace %s with %s dref:0x%x' % (current_func_name, fname, dref))
                                       response = ida_kernwin.ask_yn(1,prompt)
                                       if response < 0:
                                           bail = True
                                           break
                                       if response == 1:
                                           idaapi.set_name(function_start, fname, idaapi.SN_FORCE)
                                           print('would replace %s with %s dref:0x%x' % (current_func_name, fname, dref))
                                       did_these.append(fname)
               if bail:
                   break
                                   
   if bail:
       break
                               

                     
