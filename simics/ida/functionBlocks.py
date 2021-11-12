'''
Generate a blocks.txt file with one line per function, containing the function address, its name and the address of
each function in that block
'''
#ea = ScreenEA()

# screen might not be in code section
segs = Segments()
#print segs
#print type(segs)
dumcount = 0
# python generators....
for eh in segs:
    if dumcount == 0:
        ea = eh
        print('segment %d starts at %x' % (dumcount, eh))
    dumcount += 1

#print 'ea is %x' % ea
#print 'now loop'
# Loop through all the functions and create a file with one line per function as:
# address name
seg_start = SegStart(ea)
seg_end = SegEnd(ea)
print('seg start: %x  seg_end: %x' % (seg_start, seg_end))
blocks = open('blocks.txt', 'w')
for function_ea in Functions(seg_start, seg_end):
    #funfile.write('%s %s\n' % (hex(function_ea), GetFunctionName(function_ea)))
    print('fuction info addr: %x name: %s' % (function_ea, GetFunctionName(function_ea)))
    #items = line.split()
    #print '%s:%s' % (items[0], items[1])
    #value = int(items[0], 16)
    block_list = []
    f = idaapi.get_func(function_ea)
    fc = idaapi.FlowChart(f)
    for block in fc:
        #print 'block start is %x' % block.startEA
        block_list.append(block.startEA)
    blocks.write('%x %s ' % (function_ea, GetFunctionName(function_ea)))
    for b in block_list:
        blocks.write('%x ' % b)
    #blocks.write('%x' % ' '.join(map('%x', block_list)))
    blocks.write('\n')
blocks.close()
idaapi.qexit(0) 

print('done')
