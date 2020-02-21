import idaapi
if idaapi.IDA_SDK_VERSION <= 699:
    from idaapi import Form
else:
    from ida_kernwin import Form
class GetAddrCount(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:iAddr}
BUTTON YES* OK
BUTTON CANCEL Cancel
Get address and count for memory watch

{FormChangeCb}
<##Enter an address      :{iAddr}>
<##Enter count           :{iRawHex}>

""", {
            'iAddr': Form.NumericInput(tp=Form.FT_ADDR),
            'iRawHex': Form.NumericInput(tp=Form.FT_ADDR),
            'iButton1': Form.ButtonInput(self.OnButton1),
            'iButton2': Form.ButtonInput(self.OnButton2),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })


    def OnButton1(self, code=0):
        print("Button1 pressed")


    def OnButton2(self, code=0):
        print("Button2 pressed")


    def OnFormChange(self, fid):
        return 1

