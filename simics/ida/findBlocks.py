import json
''' create a file with one line per function containing a list of each of the function's 
    basic blocks
'''
fname = get_root_filename()
funs_fh = open(fname+'.funs') 
fun_json = json.load(funs_fh)
blocks = {}
for fun in fun_json:
    fun_addr = int(fun)
    print('name %s 0x%x' % (fun_json[fun]['name'], fun_addr))
    block_list = []
    f = idaapi.get_func(fun_addr)
    if f is not None:
        fc = idaapi.FlowChart(f)
        blocks[fun_addr] = {}
        blocks[fun_addr]['name'] = fun_json[fun]['name']
        blocks[fun_addr]['blocks'] = []
        for block in fc:
            #print 'block start is %x' % block.start_ea
            blocks[fun_addr]['blocks'].append(block.start_ea)
    else:
        print('NO function found for name %s 0x%x' % (fun_json[fun]['name'], fun_addr))
s = json.dumps(blocks, indent=4)
with open(fname+'.blocks', 'w') as fh:
    fh.write(s)
funs_fh.close()
print 'done'
