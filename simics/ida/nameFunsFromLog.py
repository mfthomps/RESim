'''
For each function, look for a reference to string containing ": START".  When found
assume that is a log message artifact containing the name of the function.  Use that
to rename the function so it matches the original C.  Intended for stripped files.
'''    
ea = get_screen_ea()
for function_ea in Functions(SegStart(ea), SegEnd(ea)):
    fun_name = GetFunctionName(function_ea)
    end = FindFuncEnd(function_ea)
    done = False
    for head in Heads(function_ea, end):
        refs = DataRefsFrom(head)
        for r in refs:
            s = GetString(r)
            if s is not None and ': START' in s:
                name = s.split(':')[0].strip()
                print(name)
                MakeNameEx(function_ea, name, 0)
                done = True
                break
        if done:
            break
                
