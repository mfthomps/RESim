import json
import idaapi
import ida_graph
import ida_gdl
def getBB(graph, bb):
    for block in graph:
        if block.start_ea <= bb and block.end_ea >= bb:
            return block.id
    return None
    
fname = get_root_filename()
funs_fh = open(fname+'.hits') 
fun_json = json.load(funs_fh)
p = idaapi.node_info_t()
p.bg_color =  0x00ff00
for fun in fun_json:
    fun_addr = int(fun)
    f = idaapi.get_func(fun_addr)
    graph = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
    for bb in fun_json[fun]:
        bb_id = getBB(graph, bb)
        if bb_id is not None:
            if bb != fun_addr:
                bb_id += 1
            ida_graph.set_node_info(fun_addr, bb_id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
            if fun_addr == 0x1bb28:
                print('funx 0x%x set bb 0x%x bb_id %d' % (fun_addr, bb, bb_id))
