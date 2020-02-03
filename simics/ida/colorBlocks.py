import json
import idaapi
import ida_graph
def getBB(graph, bb):
    for block in graph:
        if block.start_ea <= bb and block.end_ea >= bb:
            return block.id
    return None
    
fname = get_root_filename()
funs_fh = open(fname+'.hits') 
fun_json = json.load(funs_fh)
for fun in fun_json:
    fun_addr = int(fun)
    f = idaapi.get_func(fun_addr)
    graph = idaapi.FlowChart(f)
    for bb in fun_json[fun]:
        bb_id = getBB(graph, bb)
        if bb_id is not None:
            p = idaapi.node_info_t()
            p.bg_color = 0x00ff00
            ida_graph.set_node_info(bb, bb_id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
            print('fun 0x%x set bb 0x%x bb_id %d' % (fun_addr, bb, bb_id))
