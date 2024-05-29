#
#  Search a json created by findGadets.py.
#  Manually edit this file to get it to search for
#  what you want, and then run it from IDA.
#
import json
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import decode
  
def checkMov(instruct, gname, reg):
    retval = False 
    mn = decode.getMn(instruct)
    op2, op1 = decode.getOperands(instruct)
    if op1 is not None and '[' in op1 and reg in op1:
        retval = True
    if mn == 'mov' and op1 == reg:
        if (op2.startswith('e') or '[' in op2):
            print('gadget 0x%x %s' % (gname, instruct))
            retval = True
        else:
            retval = True
    return retval

def checkMovExact(instruct, gname, reg1, reg2):
    retval = False 
    mn = decode.getMn(instruct)
    op2, op1 = decode.getOperands(instruct)
    if op1 is not None and '[' in op1 and reg1 in op1:
        retval = True
    if mn == 'mov' and op1 == reg1:
        if op2 == reg2:
            print('gadget 0x%x %s' % (gname, instruct))
            retval = True
        else:
            retval = True
    return retval

def checkIndMov(instruct, gname, reg):
    retval = False 
    mn = decode.getMn(instruct)
    op2, op1 = decode.getOperands(instruct)
    if op1 is not None and '[' in op1 and reg in op1:
        retval = True
    if mn == 'mov' and op1 == reg:
        if '[' in op2 and 'e' in op2:
            print('gadget 0x%x %s' % (gname, instruct))
            retval = True
        else:
            retval = True
    return retval

def checkAdd(instruct, gname):
    retval = False 
    mn = decode.getMn(instruct)
    op2, op1 = decode.getOperands(instruct)
    if op1 is not None and '[' in op1 and 'eax' in op1:
        retval = True
    if mn == 'leave':
        retval = True
    if (mn in ['mov', 'sub', 'lea', 'shl', 'shr'] ) and op1 == 'eax':
        retval = True
    #elif mn == 'add' and op1 == 'eax':
    elif mn == 'add' and op1.startswith('e') and op2.startswith('e'):
        print('gadget 0x%x %s' % (gname, instruct))
        retval = True
    return retval



def search(fname=None):
    if fname is None:
        #fname = idaversion.get_root_file_name()
        fname = os.getenv('ida_analysis_path')
        if fname is None:
            print('No ida_analysis_path defined')
            fname = idaversion.get_input_file_path()
    print('fname is %s' % fname)  
    gadget_dict = None
    with open(fname+'.gadgets', 'r') as fh:
        gadget_dict = json.load(fh) 
    for gadget in gadget_dict:
        gname = int(gadget)
        for instruct in reversed(gadget_dict[gadget]):
            mn = decode.getMn(instruct)
            if mn == 'call':
                break
            if mn == 'leave':
                break
            #if checkMov(instruct, gname, 'edx'):
            #    break
            #if checkIndMov(instruct, gname, 'eax'):
            #    break
            #if checkAdd(instruct, gname):
            #    break
            if checkMovExact(instruct, gname, 'edx', 'ecx'):
                break
if __name__ == "__main__":
    search()
