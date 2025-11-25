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
    #print('add hap callback')
    retval = SIM_hap_add_callback(hap_type, callback, param)
    #print('done')
    return retval

def RES_hap_add_callback_obj(hap_type, cell, val, callback, val2):
    #print('add hap eh')
    retval = SIM_hap_add_callback_obj(hap_type, cell, val, callback, val2)
    #print('done')
    return retval 

def RES_hap_add_callback_obj_index(hap_type, cell, val, callback, val2, val3):
    #print('add hap index')
    retval = SIM_hap_add_callback_obj_index(hap_type, cell, val, callback, val2, val3)
    #print('done')
    return retval

def RES_hap_add_callback_obj_range(hap_type, cell, val, callback, val2, val3, maxval):
    #print('add hap range')
    retval = SIM_hap_add_callback_obj_range(hap_type, cell, val, callback, val2, val3, maxval)
    #print('done')
    return retval

def RES_hap_add_callback_index(hap_type, callback, param, breaknum):
    #print('add hap on break %d' % breaknum)
    retval = SIM_hap_add_callback_index(hap_type, callback, param, breaknum)
    #print('done')
    return retval

def RES_hap_add_callback_range(hap_type, callback, param, breaknum, max_break):
    #print('add hap on break %d max %d' % (breaknum, max_break))
    retval = SIM_hap_add_callback_range(hap_type, callback, param, breaknum, max_break)
    #print('done')
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
    #print('del breakpoint')
    SIM_delete_breakpoint(bp)
    #print('done')

def RES_delete_mode_hap(hap, dumb=None):
    SIM_hap_delete_callback_id("Core_Mode_Change", hap)

def RES_delete_mem_hap(hap, dumb=None):
    SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hap)

def RES_delete_stop_hap(hap, dumb=None):
    SIM_hap_delete_callback_id("Core_Simulation_Stopped", hap)
