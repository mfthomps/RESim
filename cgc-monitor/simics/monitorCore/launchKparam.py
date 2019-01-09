'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
'''
   Generate a RESim parameter file based on observiations made of a
   32 bit linux kernel.  Intended to be invoked from a shell script 
   that sets these environment variables:
       RUN_FROM_SNAP -- checkpoint of the system to run.  It is suggested
          that you let the system boot before creating the snapshot.
       RESIM_TARGET -- the name of the cell within the simulated system
          that is to be analyzed.  This is also used as the name of the
          newly generated parameter file, i.e., $RESIM_TARGET.param
'''
import os
CORE = '/mnt/cgc-monitor/cgc-monitor/simics/monitorCore'
ZK = '/mnt/cgc-monitor/cgc-monitor/zk/monitorLibs'
if CORE not in sys.path:
    print("using CORE of %s" % CORE)
    sys.path.append(CORE)
if ZK not in sys.path:
    print("using ZK of %s" % ZK)
    sys.path.append(ZK)
RUN_FROM_SNAP = os.getenv('RUN_FROM_SNAP')
run_command('add-directory -prepend /mnt/cgc-monitor/cgc-monitor/simics/simicsScripts')
run_command('add-directory -prepend /mnt/cgc-monitor/cgc-monitor/simics/monitorCore')
run_command('add-directory -prepend /mnt/cgc-monitor/cgc-monitor/zk/monitorLibs')
run_command('add-directory -prepend /mnt/simics/eemsWorkspace')
if RUN_FROM_SNAP is None:
    run_command('run-command-file ./targets/ubuntu.simics')
else:
    print('run from checkpoint %s' % RUN_FROM_SNAP)
    run_command('read-configuration %s' % RUN_FROM_SNAP)
run_command('run-python-file getKernelParams.py')

