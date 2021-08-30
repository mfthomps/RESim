'''
Attach debugger to localhost and Launch RESim ida client.  First color blocks is requested.
'''
import sys
import idc
import ida_dbg
here = os.path.join(os.getenv('RESIM_DIR'), 'simics', 'ida')
sys.path.append(here)
import colorBlocks
import resetBlocks
import rev
import time

ok = True
arg_count = idc.eval_idc("ARGV.count")
if arg_count > 1:
    arg1 = idc.eval_idc("ARGV[1]")
    if arg1 == 'color':
        resetBlocks.resetBlocks()
        colorBlocks.colorBlocks()
        print('did color')
    elif arg1 == 'clear':
        resetBlocks.resetBlocks()
        print('did clear')
    else:
        print('resim [color] | [clear]')
        print('  color -- clear block coloring and then color per hits files')
        print('  clear -- clear block coloring')
        ok = False
if ok:
    ida_dbg.set_remote_debugger('127.0.0.1', '9123')
    ida_dbg.load_debugger('gdb', True)
    result=ida_dbg.attach_process(0,-1) 
    print('attach result %d' % result)
    rev.RESimClient()
