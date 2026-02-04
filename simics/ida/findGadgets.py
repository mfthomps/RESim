#
#  Find gadgets in an IDA file and store as a json
#  in the RESim IDA analysis directory.
#  Conditional jumps are not yet included.
#
import idautils
import json
import idaversion
def getInstructs(block):
    insn = ida_ua.insn_t()
    ea = block.start_ea
    retval = []
    while ea < block.end_ea:
        instruct = idc.generate_disasm_line(ea, 0).lower()
        retval.append(instruct)
        idaapi.decode_insn(insn, ea)
        ea = ea + insn.size
    return retval
    
def findGadgets(fname=None):
    if fname is None:
        #fname = idaversion.get_root_file_name()
        fname = os.getenv('ida_analysis_path')
        if fname is None:
            print('No ida_analysis_path defined')
            fname = idaversion.get_input_file_path()
    gadget_dict = {}
    #for ea in idautils.Segments():
    seg_struct = ida_segment.get_segm_by_name('.text')
    seg_start = seg_struct.start_ea
    size = seg_struct.size()
    seg_end = seg_start+size
    if True:
        #start = idaversion.get_segm_attr(ea, idc.SEGATTR_START)
        #end = idaversion.get_segm_attr(ea, idc.SEGATTR_END)
        for function_ea in idautils.Functions(seg_start,  seg_end):
            f = idaapi.get_func(function_ea)
            got_ret = False
            if f is not None:
                fc = idaapi.FlowChart(f)
                for block in fc:
                    end = block.end_ea - 1
                    instruct = idc.generate_disasm_line(end, 0).lower()
                    #print('instruct %s' % instruct)
                    if instruct.startswith('ret'):
                        got_ret = True
                        #print('got ret at 0x%x' % end)
                        instruct_list = getInstructs(block)
                        gadget_name = block.start_ea
                        preds = block.preds()
                        got_pred = False
                        for prev in preds:
                            prev_end = prev.end_ea - 1
                            prev_instruct = idc.generate_disasm_line(prev_end, 0).lower()
                            if not prev_instruct.startswith('j'):
                                print('adding 0x%x to gadget 0x%x' % (prev.start_ea, end))
                                add_list = getInstructs(prev)
                                add_list.extend(instruct_list) 
                                gadget_name = prev.start_ea
                                gadget_dict[gadget_name] = add_list
                                got_pred = True
                            elif prev_instruct.startswith('jmp'):
                                jmp_list = getInstructs(prev)
                                jmp_list.extend(instruct_list)
                                gadget_name = prev.start_ea
                                gadget_dict[gadget_name] = jmp_list
                                print('adding jmp gadget 0x%x' % gadget_name)
                            # TBD separates lists or elements for conditional jumps
                        if not got_pred:
                            gadget_dict[gadget_name] = instruct_list
                       
                if not got_ret:
                    #print('did not find ret for function_ea 0x%x' % function_ea)
                    pass
            else:
                print('no fun found for function_ea 0x%x' % function_ea)
    s = json.dumps(gadget_dict)
    with open(fname+'.gadgets', 'w') as fh:
        fh.write(s) 
    print('wrote %d gadgets to %s' % (len(gadget_dict), fname))
    print('done**************')

if __name__ == "__main__":
    findGadgets()
