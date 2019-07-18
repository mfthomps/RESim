def getAddrCount(title, addr, count):
    s = """%s
    <~E~nter address:N:32:16::>
    <~E~nter count:N:32:10::>
    """ % title
    count_field = Form.NumericArgument('N', value=count)
    addr_field = Form.NumericArgument('N', value=addr)
    ok = idaapi.AskUsingForm(s, addr_field.arg, count_field.arg)
    if ok == 1:
        return addr_field.value, count_field.value
    else:
        return None, None

