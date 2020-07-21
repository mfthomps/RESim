import json
import idaapi
import ida_graph
import ida_gdl
def getBB(graph, bb):
    for block in graph:
        if block.start_ea <= bb and block.end_ea >= bb:
            return block.id
    return None

p = idaapi.node_info_t()
p.bg_color =  0xFFFFCC
fname = get_root_filename()
funs_fh = open(fname+'.funs') 
fun_json = json.load(funs_fh)
for fun in fun_json:
    fun_addr = int(fun)
    #print('fun_addr 0x%x' % fun_addr)
    f = idaapi.get_func(fun_addr)
    graph = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
    for bb in graph:
        ida_graph.set_node_info(fun_addr, bb.id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
        #print('funx 0x%x set bb_id %d' % (fun_addr, bb.id))
