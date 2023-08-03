import os
import json
import idaapi
import ida_graph
import ida_gdl
import idaversion
import idc
import ida_nalt
import resimUtils
def getBB(graph, bb):
    for block in graph:
        if block.start_ea <= bb and block.end_ea > bb:
            return block.id
    return None

def resetBlocks(in_path=None):
    p = idaapi.node_info_t()
    p.bg_color =  0xFFFFCC
    #fname = idaapi.get_root_filename()
    if in_path is None:
        #fname = idc.eval_idc("ARGV[1]")
        fname = idaversion.get_input_file_path()
    else:
        fname = in_path
    ida_analysis_path = os.getenv('ida_analysis_path')
    print('ida_analysis_path is %s' % ida_analysis_path)
    funs_file = ida_analysis_path+'.funs'
    if not os.path.isfile(funs_file):
        print('No file at %s\n Creating the database files needed by RESim.' % funs_file)
        resimUtils.dumpFuns(fname=fname)
    funs_fh = open(funs_file) 
    fun_json = json.load(funs_fh)
    print('funs_file %s' % funs_file)

    current_image_base = ida_nalt.get_imagebase()
    print('current_image_base 0x%x' % current_image_base)

    orig_image_base = os.getenv('original_image_base')
    if orig_image_base is not None:
        offset = current_image_base - int(orig_image_base,16)
    else:
        offset = 0
    for fun in fun_json:
        fun_addr = int(fun)
        fun_addr = fun_addr+offset
        #print('fun_addr 0x%x' % fun_addr)
        f = idaapi.get_func(fun_addr)
        #print('fun addr 0x%x' % fun_addr)
        #print('fun is %s' % str(f))
        if f is None:
            print('no function found for 0x%x' % fun_addr)
            break
        #print('doing function found for 0x%x' % fun_addr)
        graph = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
        for bb in graph:
            ida_graph.set_node_info(fun_addr, bb.id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
            #print('funx 0x%x set bb_id %d' % (fun_addr, bb.id))
if __name__ == '__main__':
    resetBlocks()
