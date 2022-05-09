from simics import *
import inspect
def RES_hap_delete_callback_id(hap_type, hap_num):
    #curframe = inspect.currentframe()
    #calframe = inspect.getouterframes(curframe, 2)
    #print('delete hap %d' % hap_num)
    #print('caller name:', calframe[1][3])
    SIM_hap_delete_callback_id(hap_type, hap_num)
    #print('done')

def RES_hap_add_callback(hap_type, callback, param):
    retval = SIM_hap_add_callback(hap_type, callback, param)
    return retval

def RES_hap_add_callback_obj(hap_type, cell, val, callback, val2):
    retval = SIM_hap_add_callback_obj(hap_type, cell, val, callback, val2)
    return retval 

def RES_hap_add_callback_obj_index(hap_type, cell, val, callback, val2, val3):
    retval = SIM_hap_add_callback_obj_index(hap_type, cell, val, callback, val2, val3)
    return retval

def RES_hap_add_callback_obj_range(hap_type, cell, val, callback, val2, val3, maxval):
    retval = SIM_hap_add_callback_obj_range(hap_type, cell, val, callback, val2, val3, maxval)
    return retval

def RES_hap_add_callback_index(hap_type, callback, param, breaknum):
    retval = SIM_hap_add_callback_index(hap_type, callback, param, breaknum)
    return retval

def RES_delete_breakpoint(bp):
    '''
    currentframe = inspect.currentframe()
    callgraph=inspect.getouterframes(currentframe)
    print('Call Graph for {0:s}'.format(RES_delete_breakpoint.__name__))
    for record in callgraph:
        frameinfo = inspect.getframeinfo(record[0])
        print(frameinfo.function)
    '''
    SIM_delete_breakpoint(bp)
