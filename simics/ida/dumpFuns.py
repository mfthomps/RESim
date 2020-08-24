import json
funs = {}
#ea = get_screen_ea()
#print 'ea is %x' % ea
fname = get_root_filename()
print('inputfile %s' % fname)
for ea in Segments():
    start = get_segm_start(ea)
    end = get_segm_end(ea)
    for function_ea in Functions(start,  end):
        funs[function_ea] = {}
        try:
            end = get_func_attr(function_ea, FUNCATTR_END)
            funs[function_ea]['start'] = function_ea
            funs[function_ea]['end'] = end
            funs[function_ea]['name'] = get_func_name(function_ea)
        except KeyError:
            print('failed getting attribute for 0x%x' % function_ea)
            pass

with open(fname+'.funs', "w") as fh:
    json.dump(funs, fh)
