import json
from collections import OrderedDict 
import os
import idaapi
import ida_graph
import ida_gdl
import idc
import gdbProt
import subprocess
'''
Color basic blocks to reflect whether blocks were hit during the most recent data session, or any data session.
'''
new_hit_color = 0x00ff00 
old_hit_color = 0x00ffcc 
not_hit_color = 0x00ffff
pre_hit_color = 0xccff00
def getBB(graph, bb_addr):
    for block in graph:
        if block.start_ea <= bb_addr and block.end_ea > bb_addr:
            return block
    return None
def getBBId(graph, bb):
    bb = getBB(graph, bb)
    if bb is not None:
        return bb.id
    else:
        return None
   

def doColor(latest_hits_file, all_hits_file, pre_hits_file):
    if os.path.isfile(latest_hits_file):
        with open(latest_hits_file) as funs_fh:
            latest_hits_json = json.load(funs_fh)
        print('loaded blocks from %s, got %d hits' % (latest_hits_file, len(latest_hits_json)))
    else:
        latest_hits_json = {}
    if os.path.isfile(all_hits_file):
        with open(all_hits_file) as funs_fh:
            all_hits_json = json.load(funs_fh)
        print('loaded blocks from %s, got %d functions' % (all_hits_file, len(all_hits_json)))
    else:
        all_hits_json = {}
    if os.path.isfile(pre_hits_file):
        with open(pre_hits_file) as funs_fh:
            pre_hits_json = json.load(funs_fh)
        print('loaded blocks from %s, got %d functions' % (pre_hits_file, len(pre_hits_json)))
    else:
        pre_hits_json = {}
    p = idaapi.node_info_t()
    ''' New hits '''
    p.bg_color =  new_hit_color
    num_new = 0
    graph_dict = {}
    for bb in latest_hits_json:
        #print('bb is 0x%x' % bb)
        f = idaapi.get_func(bb)
        if f not in graph_dict:
            graph_dict[f] = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
        block = getBB(graph_dict[f], bb)
        if block is not None:
            bb_id = block.id
            if bb not in all_hits_json:
                ''' first time bb has been hit in any data session '''
                p.bg_color =  new_hit_color
                ida_graph.set_node_info(f.start_ea, bb_id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
                #print('new hit fun 0x%x bb: 0x%x bb_id: %d block.start_ea 0x%x end 0x%x' % (f.start_ea, bb, bb_id, block.start_ea, block.end_ea))
                num_new += 1
            elif bb in all_hits_json:
                ''' also hit in earlier data session '''
                p.bg_color =  old_hit_color
                ida_graph.set_node_info(f.start_ea, bb_id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
                #print('old hit fun 0x%x bb: 0x%x' % (fun_addr, bb))
            else:
                print('impossible')
                exit(1)

    print('Data run generated %d new hits' % num_new)

    ''' Not hit on recent data session, but hit previously '''
    p.bg_color =  not_hit_color
    for bb in all_hits_json:
        f = idaapi.get_func(bb)
        #print('fun addr 0x%x' % fun_addr)
        if f is None:
            print('unable to get function from addr 0x%x' % bb)
            continue
        if f not in graph_dict:
            graph_dict[f] = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
        bb_id = getBBId(graph_dict[f], bb)
        if bb_id is not None:
            if bb not in latest_hits_json:
                ida_graph.set_node_info(f.start_ea, bb_id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
                #print('not hit fun 0x%x bb: 0x%x' % (fun_addr, bb))

    ''' Hit prior to start of any data session, i.e., IO setup '''
    p.bg_color =  pre_hit_color
    for bb in pre_hits_json:
        f = idaapi.get_func(bb)
        #print('fun addr 0x%x' % fun_addr)
        if f not in graph_dict:
            graph_dict[f] = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
        bb_id = getBBId(graph_dict[f], bb)
        if bb_id is not None:
            if bb not in latest_hits_json and bb not in all_hits_json:
                ida_graph.set_node_info(fun.start_ea, bb_id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
                #print('not hit fun 0x%x bb: 0x%x' % (fun_addr, bb))

def colorBlocks():
    resim_ida_data = os.getenv('RESIM_IDA_DATA')
    if resim_ida_data is None:
        print('RESIM_IDA_DATA not defined.')
    else:
        #in_path = idaapi.get_root_filename()
        in_path = idc.eval_idc("ARGV[1]")
        base = os.path.basename(in_path)
        fname = os.path.join(resim_ida_data, base, base)
        latest_hits_file = fname+'.hits' 
        if not os.path.isfile(latest_hits_file):
            ''' maybe a symbolic link, ask monitor for name '''
            #cmd = '@cgc.getCoverageFile()'
            #latest_hits_file = gdbProt.Evalx('SendGDBMonitor("%s");' % cmd).strip()
            #if not os.path.isfile(latest_hits_file):
            print('No hits file found %s' % latest_hits_file)
        else:                
            all_hits_file = fname+'.all.hits'
            pre_hits_file = fname+'.pre.hits'
            doColor(latest_hits_file, all_hits_file, pre_hits_file)
