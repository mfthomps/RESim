from ida_kernwin import Form
class SetAddrString(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:iAddr}
BUTTON YES* OK
BUTTON CANCEL Cancel
Modify memory with a string

{FormChangeCb}
<#Hint1#Enter string  :{iStr1}>
<##Enter an address      :{iAddr}>

""", {
            'iStr1': Form.StringInput(),
            'iAddr': Form.NumericInput(tp=Form.FT_ADDR),
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



