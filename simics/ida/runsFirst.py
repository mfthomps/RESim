'''
Attach debugger to localhost and Launch RESim ida client.  First color blocks if requested.
Intended to start RESim as the result of a hotkey.
'''
import sys
import os
import idc
import ida_dbg
here = os.path.join(os.getenv('RESIM_DIR'), 'simics', 'ida')
sys.path.append(here)
import colorBlocks
import resetBlocks
import rev
import time
import reHooks
import idbHooks
import dbgHooks
import subprocess

ok = True
arg_count = idc.eval_idc("ARGV.count")
if arg_count > 1:
    resim_ida_arg=idc.eval_idc("ARGV[1]")
    print('In runsFirst arg_count %d resim_ida_arg %s ' % (arg_count, resim_ida_arg))
    if resim_ida_arg == 'color':
        print('did color')
        '''
        if arg_count > 3:
            remote = idc.eval_idc("ARGV[3]")
            cmd = 'ssh %s "echo \$RESIM_IDA_DATA"' % (remote)
            ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            ida_data = ps.communicate()[0].decode('utf-8').strip()
            print('ida_data at %s' % ida_data)
            in_path = idaapi.get_root_filename()
            infile = os.path.basename(in_path)
            remote_ida_path = os.path.join(ida_data, infile)
            my_ida_path = os.path.join(os.getenv('RESIM_IDA_DATA'), infile)
            cmd = 'scp %s:%s/*.hits %s/' % (remote, remote_ida_path, my_ida_path)
            print('cmd is %s' % cmd)
            os.system(cmd)
        '''
            
        resetBlocks.resetBlocks()
        colorBlocks.colorBlocks()
        
    elif resim_ida_arg == 'clear':
        resetBlocks.resetBlocks()
        print('did clear')
    else:
        print('resim [color] | [clear]')
        print('  color -- clear block coloring and then color per hits files')
        print('  clear -- clear block coloring')
        ok = False
if ok:
    idb_hooks = idbHooks.IDBHooks()
    idb_hooks.hook()
    dbg_hooks = dbgHooks.DBGHooks()
    dbg_hooks.hook()
    ida_dbg.set_remote_debugger('127.0.0.1', '9123')
    ida_dbg.load_debugger('gdb', True)
    result=ida_dbg.attach_process(0,-1) 
    print('attach result %d' % result)
    if result == 1:
        ''' Hooks must be set from __main__, or so it seems '''
        re_hooks = reHooks.Hooks()
        re_hooks.hook()
        rev.RESimClient(re_hooks, dbg_hooks, idb_hooks)
