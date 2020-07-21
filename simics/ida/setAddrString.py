import idaapi
import idaversion
if idaapi.IDA_SDK_VERSION <= 699:
    from idaapi import Form
else:
    from ida_kernwin import Form
class SetAddrString(Form):
    def __init__(self):
        print('wtf, over')
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

    def setIt(self):
            addr = self.GetControlValue(self.iAddr)
            val = ''
            for i in range(8):
                c = idaversion.get_wide_byte(addr+i)
                if c >= 0x20 and c <= 0x7e:
                    val = val+chr(c)
                else:
                    val = val+'.'
            print('add 0%x contains %s' % (addr, val))
            self.SetControlValue(self.iStr1, val)

    def OnFormChange(self, fid):
        print('form changed')
        if fid == self.iAddr.id:
            self.setIt()
        else:
            print('but no soap')
        return 1

