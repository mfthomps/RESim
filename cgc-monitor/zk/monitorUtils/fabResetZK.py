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

from fabric.api import run, sudo, settings, env, cd, put, reboot, parallel, execute
from fabric.contrib.files import exists
from fabric.context_managers import cd
import time
'''
Stop zookeeper on each of the cluster nodes, delete its backing store, and restart.
TBD, put zk cluster node IP addresses in a config file
'''
#env.hosts = ['10.20.200.102', '10.20.200.103', '10.20.200.104']
env.hosts = ['10.20.200.152', '10.20.200.153', '10.20.200.154']
env.user = 'mike'

#@parallel
def zk_reset():
    zk_stop()
    execute(zk_clear())
    zk_start()
    return True

@parallel
def zk_stop():
    output = sudo('/etc/init.d/zookeeperService stop', pty=False)
    return True

@parallel
def zk_start():
    output = sudo('/etc/init.d/zookeeperService start', pty=False)
    return True

@parallel
def zk_clear():
    output = sudo('rm -fr /media/sdb1/zk/version*')
    output = sudo('rm -fr /media/sdb1/zk/*.out')
    output = sudo('rm -fr /media/sdb1/zk/*.log')
    output = sudo('rm -fr /media/sdb1/zk/*.log.*')
    return True 

@parallel
def zk_install():
    '''
    Install a specific version of the zookeeper server.
    NOTE the service script and the configuration files are defined 
    in the zookeeperInstall package.
    '''
    output = sudo('/etc/init.d/zookeeperService stop', pty=False)
    run('mkdir -p /tmp/zkServerPackages')
    tar = '/mnt/vmLib/bigstuff/zookeeper-3.4.7.tar.gz'
    put(tar, '/tmp/zkServerPackages')
    output = run('tar -C /mnt/cgc/zookeeper -xvf /tmp/zkServerPackages/*.gz')
    with cd('/mnt/cgc/zookeeper/zookeeper-3.4.7/src/c'):
        output = run('./configure') 
        output = run('make')
        output = sudo('make install')
    output = sudo('chmod a+rw /mnt/cgc/zookeeper/zookeeper-3.4.7')
    pkg = '/mnt/vmLib/cgcForensicsRepo/zkServerPackages/*.deb'
    put(pkg, '/tmp/zkServerPackages')
    output = sudo('dpkg -i /tmp/zkServerPackages/*.deb', pty=False)
    output = sudo('update-rc.d zookeeperService defaults')
    output = sudo('update-rc.d zookeeperService enable')


