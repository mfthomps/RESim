ea = ScreenEA()
print 'ea is %x' % ea
# Loop through all the functions and create a file with one line per function as:
# address name
funfile = open("funs.txt", "w")
for function_ea in Functions(SegStart(ea), SegEnd(ea)):
# Print the address and the function name.
    funfile.write('%s %s\n' % (hex(function_ea), GetFunctionName(function_ea)))
    print hex(function_ea), GetFunctionName(function_ea)
funfile.close()
print 'done'
