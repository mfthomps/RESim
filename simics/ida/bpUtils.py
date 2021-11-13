import idaapi
import idaversion
import ida_dbg
def disableAllBpts(exempt):
    qty = idaversion.get_bpt_qty()
    disabledSet = []
    for i in range(qty):
        bptEA = idaversion.get_bpt_ea(i)
        bptStat = idaversion.check_bpt(bptEA)
        if bptStat > 0:
            if exempt is None or exempt != bptEA:
                disabledSet.append(bptEA)
                ida_dbg.enable_bpt(bptEA, False)
    return disabledSet

def enableBpts(disabledSet):
    for ea in disabledSet:
        ida_dbg.enable_bpt(ea, True)

def setAndDisable(addr):
    bptEnabled = ida_dbg.check_bpt(addr)
    if bptEnabled < 0:
        # no breakpoint, add one
        #print 'setAndDisable no bpt at %x, add one' % addr
        ida_dbg.add_bpt(addr)
    elif bptEnabled == 0:
         # breakpoint, but not enabled
         #print 'found bpt at %x, enable it' % addr
         ida_dbg.enable_bpt(addr, True)
    else:
        #print 'breakpoint exists, use it'
        pass
    # disable all breakpoints, excempting the one we just set/enabled
    disabledSet = disableAllBpts(addr)
    return bptEnabled, disabledSet

def reEnable(addr, bptEnabled, disabledSet):
    enableBpts(disabledSet)
    #print 'back from enable'
    if bptEnabled < 0:
        ida_dbg.enable_bpt(addr, False)
        success = iad_dbg.del_bpt(addr)
        #print 'reEnable delete bpt at %x success: %d' % (addr, success)
    elif bptEnabled == 0:
        #print 'reEnable reenabling bkpt at %x' % addr
        ida_dbg.enable_bpt(addr, False)

