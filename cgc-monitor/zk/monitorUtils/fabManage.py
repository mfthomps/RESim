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

from fabric.api import run, sudo, settings, env, cd, put, reboot, parallel, quiet
from fabric.contrib.files import exists
from fabric.context_managers import cd
import socket
import os
from monitorLibs import utils
'''
Fabric based scripts from managing configuration information and utilities
needed to bootstrap the CGC monitor.  Once these are in place, the ZM (zookeeper)
command should be used to coordinate the targets.
'''

myip = utils.getMyIP()
hostbase = '10.20.200.'
hostname = socket.gethostname()
env.hosts = []
if hostname == 'ubuntuHP1':
    for i in range(151,167):
        host = hostbase+str(i)
        if i == 161:
            print('skipping %s, assuming it is still dead' % host)
            continue
        #print('host is %s' % host)
        env.hosts.append(host)
else:
    for i in range(201,217):
        host = hostbase+str(i)
        #print('host is %s' % host)
        env.hosts.append(host)
    for i in range(101,117):
        host = hostbase+str(i)
        #print('host is %s' % host)
        env.hosts.append(host)

env.user = 'mike'

#env.hosts = ['10.20.200.101']
@parallel
def check_critical():
    #output = run('/bin/echo "hi"')
    output = None
    with quiet():
        output = run('/bin/grep CRITICAL  /mnt/cgc/logs/monitors/monitor*log', warn_only=True)
    if output is not None and len(output.strip())>0:
        hostname = run('hostname')
        print('output is %s %s' % (output, hostname))

@parallel
def check_type2_missed():
    #output = run('/bin/echo "hi"')
    output = None
    with quiet():
        output = run('/bin/grep "addLogEvent but no log for thrower"  /mnt/cgc/logs/monitors/monitor*log', warn_only=True)
    if output is not None and len(output.strip())>0:
        hostname = run('hostname')
        print('output is %s %s' % (output, hostname))

@parallel
def zip_logs():
    log_dir = '/mnt/cgc/logs/'
    with cd(log_dir):
        hostname = run('hostname')
        fname = '%s-logs.tgz' % hostname
        output = run('rm -f %s' % fname)
        output = run('tar czf %s *.log monitors/' % fname)
        cmd = 'scp -o StrictHostKeyChecking=no %s:%s%s /tmp/' % (env.host_string, log_dir, fname)
        os.system(cmd)

@parallel
def check_flip():
    output = None
    with quiet():
        output = run('/bin/grep actual  /mnt/cgc/logs/monitors/monitor*log', warn_only=True)
        lines = output.splitlines()
        i = 0
        while i < len(lines):
            if len(lines[i].strip()) == 0:
                i += 1
                continue
            part = lines[i].split(' - ')[2]
            parts = part.split()
            try:
                neg_eip = parts[5].rstrip(',')
                act_eip = parts[8].rstrip(',')
            except:
                print('no part 5 in %s, part was %s' % (lines[i], part))

            part = lines[i+1].split(' - ')[2]
            parts = part.split()
            try:
                neg_reg = parts[7].rstrip(',')
                act_reg = parts[10].rstrip(',')
            except:
                print('no part 5 in %s, part was %s' % (lines[i+1], part))
            if (neg_eip == act_reg and neg_reg == act_eip):
                hostname = run('hostname')
                print('%s: %s %s %s %s' % (hostname, neg_eip, act_eip, neg_reg, act_reg))
            i += 2

  
@parallel
def change_craff():
    output = run("/bin/sed -i 's/cgc-freebsd64.craff/cgc-bsd64-nohv.craff/g' /mnt/simics/simicsWorkspace/cgc3_bsd64_snapshot.ckpt/config")
    output = run('/bin/mv /mnt/simics/simicsWorkspace/cgc3_bsd64_snapshot.ckpt /mnt/simics/simicsWorkspace/cgc3_bsd64_snapshot-nohv.ckpt')
    output = run('/bin/mv /mnt/simics/simicsWorkspace/cgc-freebsd64.craff /mnt/simics/simicsWorkspace/cgc-freebsd64-nohv.craff')

@parallel
def rm_acpi():
    output=sudo('rmmod acpi_pad')

def set_zk_host():
    '''
    Define the zookeeper cluster that each target should reference
    '''
    host_string='10.20.200.102:2181,10.20.200.103:2181,10.20.200.104:2181'
    output = run('/bin/echo  "%s" >/mnt/cgc/zk_hosts.txt' % host_string, warn_only=True)
    return True

@parallel
def stop_zk_client():
    '''
    Each target runs a zk client via which it gets instructions.  Stop that on each target.
    '''
    output = sudo('/etc/init.d/zkShellService stop', warn_only=True)
    print output
    return True

@parallel
def start_zk_client():
    '''
    Each target runs a zk client via which it gets instructions.  Start that on each target.
    '''
    output = sudo('/etc/init.d/zkShellService start', pty=False)
    print output
    return True

@parallel
def update_build_utils():
    '''
    The monitor-build-utils includes utilities that distribute and update debian packages to targets,
    use this when those utilties change, vice relying on chickens, eggs and luck.
    '''
    output = run('sudo dpkg -i /mnt/vmLib/cgcForensicsRepo/monitorPackages_cfe/cgc-monitor-build-utils*.deb', warn_only=True)
    return True

@parallel
def mount_vm_lib():
    '''
    This happens as part of the core monitor scripts, but also must happen before any of those are available to the targets.
    '''
    output = run('mountVmLib', warn_only=True)
    return True

@parallel
def shutdown_monitor():
    '''
    Normally done via ZM, but if zookeeper is sick...
    '''
    output = run('shutdownMonitor', warn_only=True)
    return True

@parallel
def update_zk_client():
    '''
    Each target runs a zk client via which it gets instructions.  Update that on each target.
    '''
    output = run('sudo dpkg -i /mnt/vmLib/cgcForensicsRepo/monitorPackages_cfe/cgc-monitor-zk-shell*.deb', warn_only=True)
    return True

@parallel
def show_free():
    output = run("free -m | grep buffers/cache: | awk '{print $4}'", warn_only=True)
    return True

@parallel
def hack_it():
    log_dir = '/mnt/cgc/logs/'
    with cd(log_dir):
        output = run('grep "switch to indirect" auto*', warn_only=True)
        output = run('grep "is indirect reg, track" monitors/mon*', warn_only=True)
    return True

@parallel
@parallel
def rm_vmxmon():
    '''
    Remove the simics VMX kernel module so that it will be rebuilt on each target
    '''
    output = sudo('rmmod vmxmon', warn_only=True)
    return True

@parallel
def novmm_craff():
    ws = '/mnt/simics/simicsWorkspace'
    for i in range(12):
        cws = ws+'%d' % i
        with cd(cws):
            run('ln -s ../simicsWorkspace/cgc-freebsd64-nohv.craff cgc-bsd64-nohv.craff')

@parallel
def stopTmux():
    output = run('tmux kill-server', warn_only=True)
    return True

@parallel
def startAutoTmux():
    output = run('idaServerDebugSessions.sh auto', warn_only=True)
    return True

@parallel
def add_holt():

   #output = sudo('adduser --disabled-password --gecos "" hso', warn_only=True)
   #output = sudo('adduser hso sudo', warn_only=True)
   #output = sudo('su hso -c "mkdir -p ~/.ssh"')
   output = sudo('ls')
   #output = sudo('sudo su - hso -c "ls -l"', warn_only=True)
   #output = sudo('su - hso -c "echo \" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCvjJlDCXzZuKXia9+2GmQGEwnx2pfVq6fUvBedmf7vzbvEXcHCSuELM5YBnRukrTOLIpkNDzomry2SOa2rYlM8uJNbdiwQ3aRRzqdkI00kFDsP3EJWXSStWxL6qGhfBqnJeKH53+0dXlGbvykXSM9us2p9zDmXNyhZUbxT5Sxc+XwOxlaZe8O0pd946JUSWOwoPww07XaOU6T+rofIM6oOdHR3iTvldFRj62eP6in9xMS5mGgJlVlOOvz84I5gQuQgoY+LfXFqCHhQJ8Lrk+/BDKLd/a53+5JiwSjOlc+RLFP1m3afaxqp7AtfE+sUMq8tdMo8aU2hOQ3ikgRZyAe6URqE5qfJDbpkStwibDw2dd/lbG41gyUV44LQXHoxUtubfyI2H4gY85yh+iXPR//ZbZApQ6rvCBowz7rT/0vRFi+ERuJ/VXXURQJ9QLSGYbIyL4K8lkRm+ZNwAH/PWRtlqB3fGbGpnXiGbCk9H7EOisqkZ1+SG3+s6xtx8cMJDpNyMWVaD78DXTx76+/JuFgBnAIh4XE1j4rlssgWLBC/txj0QdsgG3qx9JpYnQqQsTkeDt8x5aOQzr/eS7lCTtPWWOOBhHeGVXK9FOP2rcji0Vh0ptzCpTKJ20oOcNupGYs/wrYbn2HCQs2zebpYdq+mDaR7iMpaDJNw2sNLk0wDzQ== CGC Certificate\" >~/.ssh/authorized_keys"')

   #output = sudo('su - hso -c "echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCvjJlDCXzZuKXia9+2GmQGEwnx2pfVq6fUvBedmf7vzbvEXcHCSuELM5YBnRukrTOLIpkNDzomry2SOa2rYlM8uJNbdiwQ3aRRzqdkI00kFDsP3EJWXSStWxL6qGhfBqnJeKH53+0dXlGbvykXSM9us2p9zDmXNyhZUbxT5Sxc+XwOxlaZe8O0pd946JUSWOwoPww07XaOU6T+rofIM6oOdHR3iTvldFRj62eP6in9xMS5mGgJlVlOOvz84I5gQuQgoY+LfXFqCHhQJ8Lrk+/BDKLd/a53+5JiwSjOlc+RLFP1m3afaxqp7AtfE+sUMq8tdMo8aU2hOQ3ikgRZyAe6URqE5qfJDbpkStwibDw2dd/lbG41gyUV44LQXHoxUtubfyI2H4gY85yh+iXPR//ZbZApQ6rvCBowz7rT/0vRFi+ERuJ/VXXURQJ9QLSGYbIyL4K8lkRm+ZNwAH/PWRtlqB3fGbGpnXiGbCk9H7EOisqkZ1+SG3+s6xtx8cMJDpNyMWVaD78DXTx76+/JuFgBnAIh4XE1j4rlssgWLBC/txj0QdsgG3qx9JpYnQqQsTkeDt8x5aOQzr/eS7lCTtPWWOOBhHeGVXK9FOP2rcji0Vh0ptzCpTKJ20oOcNupGYs/wrYbn2HCQs2zebpYdq+mDaR7iMpaDJNw2sNLk0wDzQ== hso\" >~/.ssh/authorized_keys"')
   


