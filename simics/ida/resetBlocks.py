import json
import idaapi
import ida_graph
import ida_gdl
import idaversion
def getBB(graph, bb):
    for block in graph:
        if block.start_ea <= bb and block.end_ea > bb:
            return block.id
    return None

p = idaapi.node_info_t()
p.bg_color =  0xFFFFCC
fname = get_root_filename()
funs_fh = open(fname+'.funs') 
funs_file = fname+'.funs'
if not os.path.isfile(funs_file):
        ''' maybe a symbolic link, ask monitor for name '''
        cmd = '@cgc.getCoverageFile()'
        latest_funs_file = gdbProt.Evalx('SendGDBMonitor("%s");' % cmd).strip()
        print('no file %s, monitor says %s' % (funs_file, latest_funs_file))
        
command = "@cgc.getSOFromFile('%s')" % fname
simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
print('so stuff: %s' % simicsString) 
if ':' in simicsString:
    adders = simicsString.split(':')[1]
    start = adders.split('-')[0]
    try:
        start_hex = int(start,16)
    except ValueError:
        print('could not get hex from %s' % start)
        exit(1)
else:
    exit(1)


fun_json = json.load(funs_fh)
print('funs_file %s' % funs_file)
for fun in fun_json:
    fun_addr = int(fun)+start_hex
    #print('fun_addr 0x%x' % fun_addr)
    f = idaapi.get_func(fun_addr)
    #print('fun addr 0x%x' % fun_addr)
    #print('fun is %s' % str(f))
    if f is None:
        #print('no function found for 0x%x' % fun_addr)
        continue
    print('doing function found for 0x%x' % fun_addr)
    graph = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
    for bb in graph:
        ida_graph.set_node_info(fun_addr, bb.id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
        #print('funx 0x%x set bb_id %d' % (fun_addr, bb.id))
