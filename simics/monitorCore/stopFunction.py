'''
Element in a chain of functions to be invoked from a stop hap.
'''
def runFun(f, cb_param=None):
        if len(f.args) == 0:
            f.fun()
        elif len(f.args) == 1 and f.args[0]=='cb_param':
            ''' the function handling the stop hap has provided the parameter rather than the flist creator '''
            f.fun(cb_param)
        elif len(f.args) == 1:
            f.fun(f.args[0])
        elif len(f.args) == 2:
            f.fun(f.args[0], f.args[1])
        elif len(f.args) == 3:
            f.fun(f.args[0], f.args[1], f.args[2])

def allFuns(flist):
    for f in flist:
        runFun(f)

class StopFunction():
    def __init__(self, fun, args, nest=True, match_pid=False):
        ''' the function '''
        self.fun = fun
        self.args = args
        ''' nest implies the function should be invoked with the flist as the parameter '''
        self.nest = nest
        self.match_pid = match_pid

        
    def run(self, flist, wrong_pid=False, cb_param=None):
        if self.fun is None:
            print('Error in stopFunction, no function defined')
        elif self.nest:
            self.fun(flist) 
        else:
            ''' TBD assume remaining functions are not hap-related'''
            ''' args is a list of parameters.  likely a better way to hack this '''
            runFun(self, cb_param=cb_param)
            for f in flist:
                if not (wrong_pid and f.match_pid):
                    runFun(f)

    def getFun(self):
        return self.fun
