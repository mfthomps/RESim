import json
funs = {}
ea = get_screen_ea()
print 'ea is %x' % ea
fname = GetInputFile()
print('inputfile %s' % fname)
for function_ea in Functions(SegStart(ea), SegEnd(ea)):
    funs[function_ea] = {}
    end = GetFunctionAttr(function_ea, FUNCATTR_END)
    funs[function_ea]['start'] = function_ea
    funs[function_ea]['end'] = end
    funs[function_ea]['name'] = GetFunctionName(function_ea)

with open(fname+'.funs', "w") as fh:
    json.dump(funs, fh)
