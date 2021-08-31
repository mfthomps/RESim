import json
from collections import OrderedDict 
import os
import ida_dbg
import idaapi
import ida_graph
import ida_gdl
import gdbProt
'''
Get the branches not taken
'''
def getBB(graph, bb_addr):
    for block in graph['blocks']:
        if block['start_ea'] <= bb_addr and block['end_ea'] > bb_addr:
            return block
    return None
def getBBId(graph, bb):
    bb = getBB(graph, bb)
    if bb is not None:
        return bb.id
    else:
        return None
   

def doEdges(latest_hits_file, all_hits_file, pre_hits_file, start_hex):
    if os.path.isfile(latest_hits_file):
        with open(latest_hits_file) as funs_fh:
            latest_hits_json = json.load(funs_fh)
        print('loaded blocks from %s, got %d functions' % (latest_hits_file, len(latest_hits_json)))
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
    edges = OrderedDict()
    prog_name = all_hits_file.split('.')[0]
    blocks_file = '%s.blocks' % prog_name
    blocks_json = {}
    if not os.path.isfile(blocks_file):
        print('No blocks file at %s' % blocks_file) 
        return
    with open(blocks_file) as blocks_fh:
        blocks_json = json.load(blocks_fh)
    
    for fun in latest_hits_json:
        fun_addr = int(fun)
        f = idaapi.get_func(fun_addr)
        #print('fun addr 0x%x' % fun_addr)
        #graph = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
        graph = blocks_json[fun]
        ''' get edges leaving all hit blocks '''
        ''' edges[branch_to] = branch_from '''
        ''' retain order of hits in list of branches not taken '''
        for bb_addr in latest_hits_json[fun]:
            ''' get the BB and check its branch-to's '''
            block = getBB(graph, bb_addr)
            if block is not None:
                for s in block['succs']:
                    if s not in latest_hits_json[fun] and not (fun in pre_hits_json and s in pre_hits_json[fun]) and s not in edges:
                        #print('added edges[0%x] block 0x%x block.end_ea 0x%x bb_addr was 0x%x ' % (s.start_ea, block.start_ea, block.end_ea, bb_addr))
                        ''' branch from block was not hit ''' 
                        edges[s] = block['start_ea']
    return edges

def getEdges():
    ''' return list of branches not taken '''
    fname = idaapi.get_root_filename()
    latest_hits_file = fname+'.hits' 
    if not os.path.isfile(latest_hits_file):
        ''' maybe a symbolic link, ask monitor for name '''
        cmd = '@cgc.getCoverageFile()'
        latest_hits_file = gdbProt.Evalx('SendGDBMonitor("%s");' % cmd).strip()
        if not os.path.isfile(latest_hits_file):
            print('No hits file found %s' % latest_hits_file)
            return
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
            return
            
    all_hits_file = fname+'.all.hits'
    pre_hits_file = fname+'.pre.hits'
    edges = doEdges(latest_hits_file, all_hits_file, pre_hits_file, start_hex)
    return edges
