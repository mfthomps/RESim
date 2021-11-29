import json
import idc
import idaversion
import idautils
def dumpFuns(fname=None):
    funs = {}
    #ea = get_screen_ea()
    #print 'ea is %x' % ea
    if fname is None:
        fname = idaversion.get_root_file_name()
    print('dumpFuns inputfile %s' % fname)
    for ea in idautils.Segments():
        start = idaversion.get_segm_attr(ea, idc.SEGATTR_START)
        end = idaversion.get_segm_attr(ea, idc.SEGATTR_END)
        for function_ea in idautils.Functions(start,  end):
            funs[function_ea] = {}
            try:
                end = idc.get_func_attr(function_ea, idc.FUNCATTR_END)
                funs[function_ea]['start'] = function_ea
                funs[function_ea]['end'] = end
                funs[function_ea]['name'] = idaversion.get_func_name(function_ea)
            except KeyError:
                print('failed getting attribute for 0x%x' % function_ea)
                pass
    
    with open(fname+'.funs', "w") as fh:
        json.dump(funs, fh)
