import idaapi
import idaversion
if idaapi.IDA_SDK_VERSION <= 699:
    from idaapi import Form
else:
    from ida_kernwin import Form
import idc
class SetAddrValue(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:iRawHex}
BUTTON YES* OK
BUTTON CANCEL Cancel
Modify word

{FormChangeCb}
<##Enter hex value       :{iRawHex}>
<##Enter an address      :{iAddr}>
<##Enter an offset       :{iOffset}>

""", {
            'iRawHex': Form.NumericInput(tp=Form.FT_RAWHEX),
            'iAddr': Form.NumericInput(tp=Form.FT_ADDR),
            'iOffset': Form.NumericInput(tp=Form.FT_ADDR),
            'iButton1': Form.ButtonInput(self.OnButton1),
            'iButton2': Form.ButtonInput(self.OnButton2),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })


    def OnButton1(self, code=0):
        pass


    def OnButton2(self, code=0):
        pass

    def OnFormChange(self, fid):
        if fid == self.iAddr.id:
            addr = self.GetControlValue(self.iAddr)
            offset = self.GetControlValue(self.iOffset)
            new_addr = addr+offset
            val = idaversion.get_wide_dword(new_addr)
            print('add 0%x contains 0x%x' % (new_addr, val))
            self.SetControlValue(self.iRawHex, val)
        return 1
'''
sav = SetAddrValue()
sav.Compile()
sav.iAddr.value = 0xb5f28680
val = idaversion.get_wide_dword(sav.iAddr.value)
sav.iRawHex.value = val
sav.Execute()

'''
