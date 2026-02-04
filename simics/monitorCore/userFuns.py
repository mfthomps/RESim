import os
'''
User-defined memsomething functions from a file:
    program fun_name value_type param1 param2
Currently only supports string copy-type functions where param1 is the destination.
'''
class FunDef():
    def __init__(self, program, fun_name, value_type, param1, param2):
        self.program = program
        self.fun_name = fun_name
        self.value_type = value_type
        self.param1 = param1
        self.param2 = param2

class UserFuns():
    def __init__(self, fun_file, cpu, mem_utils, lgr):
        self.lgr = lgr
        self.mem_utils = mem_utils
        self.cpu = cpu
        if not os.path.isfile(fun_file):
            self.lgr.error('userFuns no file at %s' % fun_file)
            return
        self.fun_defs = []
        with open(fun_file) as fh:
            self.lgr.debug('userFuns reading from %s' % fun_file)
            #some-authd decrypt_value string src dest
            for line in fh:
                line = line.strip()
                if line.startswith('#'):
                    continue
                parts = line.split()
                program = parts[0]            
                fun_name = parts[1]            
                value_type = parts[2]            
                param1 = parts[3]
                param2 = parts[4]
                fun_rec = FunDef(program, fun_name, value_type, param1, param2)
                self.fun_defs.append(fun_rec)

    def isFun(self, fun_name):
        retval = False
        for fun_rec in self.fun_defs:
            if fun_rec.fun_name == fun_name:
                 retval = True
                 break
        self.lgr.debug('userFuns isFun %s %r' % (fun_name, retval))
        return retval

    def getParams(self, param_list, fun_name, mem_something):
        retval = None
        for fun_rec in self.fun_defs:
            if fun_rec.fun_name == fun_name:
                if fun_rec.value_type  == 'string':
                    if fun_rec.param2 == 'src':
                        mem_something.src = param_list[1] 
                        mem_something.length = self.mem_utils.getStrLen(self.cpu, mem_something.src)
                        if fun_rec.param1 == 'dest':
                            mem_something.dest = param_list[0] 
                            self.lgr.debug('userFuns getParams src 0x%x length 0x%x dest 0x%x' % (mem_something.src, mem_something.length, mem_something.dest))
                        else:
                            self.lgr.error('userFuns not finished, param2 not dest')
                    else:
                        self.lgr.error('userFuns not finished, param1 not src')
                else:
                    self.lgr.error('userFuns can only handle value type of string for now')
                    return False

