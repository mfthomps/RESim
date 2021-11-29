import os
import json
import idaapi
import ida_graph
import ida_gdl
import idaversion
import idc
import resimUtils
def getBB(graph, bb):
    for block in graph:
        if block.start_ea <= bb and block.end_ea > bb:
            return block.id
    return None

def resetBlocks():
    p = idaapi.node_info_t()
    p.bg_color =  0xFFFFCC
    #fname = idaapi.get_root_filename()
    fname = idc.eval_idc("ARGV[1]")
    funs_file = fname+'.funs'
    if not os.path.isfile(funs_file):
        print('No file at %s\n Creating the database files needed by RESim.' % funs_file)
        resimUtils.dumpFuns(fname=fname)
    funs_fh = open(funs_file) 
    fun_json = json.load(funs_fh)
    print('funs_file %s' % funs_file)
    for fun in fun_json:
        fun_addr = int(fun)
        #print('fun_addr 0x%x' % fun_addr)
        f = idaapi.get_func(fun_addr)
        #print('fun addr 0x%x' % fun_addr)
        #print('fun is %s' % str(f))
        if f is None:
            #print('no function found for 0x%x' % fun_addr)
            continue
        #print('doing function found for 0x%x' % fun_addr)
        graph = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
        for bb in graph:
            ida_graph.set_node_info(fun_addr, bb.id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
            #print('funx 0x%x set bb_id %d' % (fun_addr, bb.id))
