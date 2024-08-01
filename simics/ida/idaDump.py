import resimUtils
import ida_auto
import ida_pro
import subprocess
ida_auto.auto_wait()
ida_target = os.getenv('ida_target_path')
if ida_target is None:
    print('No ida_target_path found.  exit.')
else:
    cmd = 'file %s' % ida_target
    ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    file_cmd_output = ps.communicate()[0].decode('utf-8').strip()
    print('output: %s' % file_cmd_output)
    if 'stripped' in file_cmd_output:
        resimUtils.renameFromLogger()
    else: 
        print('Not stripped, did not rename functions.')
    resimUtils.dumpFuns()
    resimUtils.dumpBlocks()
    ida_pro.qexit(0)
