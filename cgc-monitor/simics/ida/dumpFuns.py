ea = ScreenEA()
print 'ea is %x' % ea
# Loop through all the functions and create a file with one line per function as:
# address name
fname = GetInputFile()
print('inputfile %s' % fname)
funfile = open(fname+'.funs', "w")
for function_ea in Functions(SegStart(ea), SegEnd(ea)):
# Print the address and the function name.
    funfile.write('%s %s\n' % (hex(function_ea), GetFunctionName(function_ea)))
    print hex(function_ea), GetFunctionName(function_ea)
print hex(SegEnd(ea)), 'end'
funfile.close()
print 'done'
