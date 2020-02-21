import idaapi
import idc
import idaversion
def disableAllBpts(exempt):
    qty = idaversion.get_bpt_qty()
    disabledSet = []
    for i in range(qty):
	bptEA = idaversion.get_bpt_ea(i)
        bptStat = idaversion.check_bpt(bptEA)
	if bptStat > 0:
	    if exempt is None or exempt != bptEA:
	        disabledSet.append(bptEA)
	        idc.EnableBpt(bptEA, False)
    return disabledSet

def enableBpts(disabledSet):
    for ea in disabledSet:
	idc.EnableBpt(ea, True)

def setAndDisable(addr):
    bptEnabled = idc.CheckBpt(addr)
    if bptEnabled < 0:
	# no breakpoint, add one
	#print 'setAndDisable no bpt at %x, add one' % addr
	idc.AddBpt(addr)
    elif bptEnabled == 0:
	# breakpoint, but not enabled
	#print 'found bpt at %x, enable it' % addr
        idc.EnableBpt(addr, True)
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
        idc.EnableBpt(addr, False)
        success = idc.DelBpt(addr)
        #print 'reEnable delete bpt at %x success: %d' % (addr, success)
    elif bptEnabled == 0:
        #print 'reEnable reenabling bkpt at %x' % addr
	idc.EnableBpt(addr, False)

