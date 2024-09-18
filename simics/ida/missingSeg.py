#
#  IDA gets confused about memory segments.  Help if fill in the gaps
#
import ida_dbg
import idautils
import simpleDialog
import idc
def findMissing():
    segs = idautils.Segments()
    #print segs
    #print type(segs)
    dumcount = 0
    for eh in segs:
        seg_end = idc.get_segm_end(eh)
        #print('segment %d starts at %x ends 0x%x' % (dumcount, eh, seg_end))
        if dumcount == 0:
            mem_end = seg_end
        elif dumcount == 1:
            load_start = eh
            if (load_start - mem_end) > 10:
                new_start = mem_end
                new_end = load_start
                # start at zero because IDA will use this manual region on the next start as the memory.  
                line = 'IDA is confused and is missing a memory area.  Use Debugger/ Manual Region to add region from 0 to 0x%x' % (new_end)
                print('would add new region to fill in from 0 to 0x%x' % (new_end))
                ok = simpleDialog.simpleDialog(line)
                this, that = ok.Compile()
                ok.Execute()
            
        dumcount += 1
