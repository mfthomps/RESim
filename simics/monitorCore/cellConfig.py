from simics import *
class CellConfig():
    '''
    Manage the Simics simulation cells (boxes), CPU's (processor cores).
    TBD expand for multi-processor cells
    '''
    cell_cpu = {}
    cpu_cell = {}
    cell_cpu_list = {}
    cell_context = {}
    def __init__(self, comp_list, lgr):
        self.cells = list(comp_list)
        self.lgr = lgr
        self.loadCellObjects()

    def loadCellObjects(self):
        for cell_name in self.cells:
            self.lgr.debug('CellConfig loadCellObjects cell_name %s' % cell_name)
            obj = SIM_get_object(cell_name)
            self.cell_context[cell_name] = obj.cell_context

        for cell_name in self.cells:
            cmd = '%s.get-processor-list' % cell_name
            proclist = SIM_run_command(cmd)
            cpu = SIM_get_object(proclist[0])
            self.cell_cpu[cell_name] = cpu
            self.cpu_cell[cpu] = cell_name
            self.cell_cpu_list[cell_name] = []
            for proc in proclist:
                self.cell_cpu_list[cell_name].append(SIM_get_object(proc))

    def cpuFromCell(self, cell_name):
        ''' simplification for single-core sims '''
        return self.cell_cpu[cell_name]

    def getCells(self):
        return self.cells

    def cellFromCPU(self, cpu):
        return self.cpu_cell[cpu]
        
