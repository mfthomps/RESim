''' create a file with one line per function containing a list of each of the function's 
    basic blocks
'''
funs = open('funs.txt', 'r')
blocks = open('blocks.txt', 'w')
for line in funs:
    items = line.split()
    #print '%s:%s' % (items[0], items[1])
    value = int(items[0], 16)
    block_list = []
    f = idaapi.get_func(value)
    fc = idaapi.FlowChart(f)
    for block in fc:
        #print 'block start is %x' % block.startEA
        block_list.append(block.startEA)
    blocks.write('%s %s ' % (items[0], items[1]))
    blocks.write('%s' % ' '.join(map(str, block_list)))
    blocks.write('\n')
blocks.close()
print 'done'
