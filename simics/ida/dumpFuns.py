import json
funs = {}
ea = get_screen_ea()
print 'ea is %x' % ea
fname = get_root_filename()
print('inputfile %s' % fname)
start = get_segm_start(ea)
end = get_segm_end(ea)
for function_ea in Functions(start,  end):
    funs[function_ea] = {}
    end = get_func_attr(function_ea, 4)
    funs[function_ea]['start'] = function_ea
    funs[function_ea]['end'] = end
    funs[function_ea]['name'] = get_func_name(function_ea)

with open(fname+'.funs', "w") as fh:
    json.dump(funs, fh)
