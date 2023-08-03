import resimUtils
import ida_auto
import ida_pro
ida_auto.auto_wait()
resimUtils.dumpFuns()
resimUtils.dumpBlocks()
ida_pro.qexit(0)
