import idaapi
import idc
def getOffset():
    '''
    Assuming an offset, e.g., "var_11" is highlighted, and
    assuming bp is proper, get the calculated address.
    '''
    retval = None
    ip = idc.ScreenEA()
    
    print('ip is 0x%x' % ip)
    highlighted = idaapi.get_highlighted_identifier()
    print('highlighted is %s' % highlighted)
    
    ov0 = idc.GetOpnd(ip, 0)
    ov1 = idc.GetOpnd(ip, 1)
    print('op0 %s  op1 %s' % (ov0, ov1))
    
    if highlighted in ov0:
        index = 0
        want = ov0
    else:
        index = 1
        want = ov1
    ''' Convert to numberic from symbol '''
    idc.OpSeg(ip, 0)
    if '[' in want and '+' in want or '-' in want:
        op = idc.GetOpnd(ip, index)
        print('op is %s' % op)
        val = op.split('[', 1)[1].split(']')[0]
        print('val %s' % val)
        if '+' in val:
            reg,value = val.split('+')
        else:
            reg,value = val.split('-')
        reg_val = idc.GetRegValue(reg)
        try:
            value = value.strip('h')
            value = int(value, 16)
        except:
            print('unable to parse int from %s' % value)
            idc.OpStkvar(ip, 0)
            return retval
        
        if '+' in val:
            retval = reg_val + value
        else:
            retval = reg_val - value
        print('effective addr is 0x%x' % retval)
    
    ''' Convert back to symbol, e.g., var_11'''
    idc.OpStkvar(ip, 0)
    return retval

def isHighlightedEffective():
    ip = idc.ScreenEA()
    instr = idc.GetDisasm(ip)
    if '[' in instr:
        val = instr.split('[', 1)[1].split(']')[0]
        highlighted = idaapi.get_highlighted_identifier()
        if highlighted in val:
            return True
        else:
            return False
        
    
