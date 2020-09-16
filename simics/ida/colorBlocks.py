import json
from collections import OrderedDict 
import os
import idaapi
import ida_graph
import ida_gdl
import gdbProt
'''
Color basic blocks to reflect whether blocks were hit during the most recent data session, or any data session.
'''
new_hit_color = 0x00ff00 
old_hit_color = 0x00ffcc 
not_hit_color = 0x00ffff
pre_hit_color = 0xccff00
def getBB(graph, bb_addr):
    for block in graph:
        if block.start_ea <= bb_addr and block.end_ea >= bb_addr:
            return block
    return None
def getBBId(graph, bb):
    bb = getBB(graph, bb)
    if bb is not None:
        return bb.id
    else:
        return None
   

def doColor(latest_hits_file, all_hits_file, pre_hits_file):
    with open(latest_hits_file) as funs_fh:
        latest_hits_json = json.load(funs_fh)
    print('loaded blocks from %s, got %d functions' % (latest_hits_file, len(latest_hits_json)))
    with open(all_hits_file) as funs_fh:
        all_hits_json = json.load(funs_fh)
    print('loaded blocks from %s, got %d functions' % (all_hits_file, len(all_hits_json)))
    with open(pre_hits_file) as funs_fh:
        pre_hits_json = json.load(funs_fh)
    print('loaded blocks from %s, got %d functions' % (pre_hits_file, len(pre_hits_json)))
    p = idaapi.node_info_t()
    ''' New hits '''
    p.bg_color =  new_hit_color
    num_new = 0
    edges = OrderedDict()
    for fun in latest_hits_json:
        fun_addr = int(fun)
        f = idaapi.get_func(fun_addr)
        #print('fun addr 0x%x' % fun_addr)
        graph = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
        ''' get edges leaving all hit blocks '''
        ''' edges[branch_to] = branch_from '''
        ''' retain order of hits in list of branches not taken '''
        for bb_addr in latest_hits_json[fun]:
            ''' get the BB and check its branch-to's '''
            block = getBB(graph, bb_addr)
            if block is not None:
                for s in block.succs():
                    if s.start_ea not in latest_hits_json[fun] and s.start_ea not in edges:
                        ''' branch from block was not hit ''' 
                        edges[s.start_ea] = block.start_ea
                                          
        for bb in latest_hits_json[fun]:
            bb_id = getBBId(graph, bb)
            if bb_id is not None:
                if bb != fun_addr:
                    bb_id += 1
                if fun not in all_hits_json or bb not in all_hits_json[fun]:
                    ''' first time bb has been hit in any data session '''
                    p.bg_color =  new_hit_color
                    ida_graph.set_node_info(fun_addr, bb_id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
                    print('new hit fun 0x%x bb: 0x%x' % (fun_addr, bb))
                    num_new += 1
                elif bb in all_hits_json[fun]:
                    ''' also hit in earlier data session '''
                    p.bg_color =  old_hit_color
                    ida_graph.set_node_info(fun_addr, bb_id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
                    #print('old hit fun 0x%x bb: 0x%x' % (fun_addr, bb))
                else:
                    print('impossible')
                    exit(1)

    print('Data run generated %d new hits' % num_new)
    print('Unhit edges')

    ''' Not hit on recent data session, but hit previously '''
    p.bg_color =  not_hit_color
    for fun in all_hits_json:
        fun_addr = int(fun)
        f = idaapi.get_func(fun_addr)
        #print('fun addr 0x%x' % fun_addr)
        if f is None:
            print('unable to get function from addr 0x%x' % fun_addr)
            continue
        graph = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
        for bb in all_hits_json[fun]:
            bb_id = getBBId(graph, bb)
            if bb_id is not None:
                if bb != fun_addr:
                    bb_id += 1
                if fun not in latest_hits_json or bb not in latest_hits_json[fun]:
                    ida_graph.set_node_info(fun_addr, bb_id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
                    #print('not hit fun 0x%x bb: 0x%x' % (fun_addr, bb))

    ''' Hit prior to start of any data session, i.e., IO setup '''
    p.bg_color =  pre_hit_color
    for fun in pre_hits_json:
        fun_addr = int(fun)
        f = idaapi.get_func(fun_addr)
        #print('fun addr 0x%x' % fun_addr)
        graph = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
        for bb in pre_hits_json[fun]:
            bb_id = getBBId(graph, bb)
            if bb_id is not None:
                if bb != fun_addr:
                    bb_id += 1
                if (fun not in latest_hits_json or bb not in latest_hits_json[fun]) and (fun not in all_hits_json or bb not in all_hits_json[fun]):
                    ida_graph.set_node_info(fun_addr, bb_id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
                    #print('not hit fun 0x%x bb: 0x%x' % (fun_addr, bb))
    return edges

def colorBlocks():
    ''' return list of branches not taken '''
    fname = idaapi.get_root_filename()
    latest_funs_file = fname+'.hits' 
    if not os.path.isfile(latest_funs_file):
        ''' maybe a symbolic link, ask monitor for name '''
        cmd = '@cgc.getCoverageFile()'
        latest_funs_file = gdbProt.Evalx('SendGDBMonitor("%s");' % cmd).strip()
        if not os.path.isfile(latest_funs_file):
            print('No hits file found %s' % latest_funs_file)
            return
    all_hits_file = fname+'.all.hits'
    pre_hits_file = fname+'.pre.hits'
    edges = doColor(latest_funs_file, all_hits_file, pre_hits_file)
    return edges
