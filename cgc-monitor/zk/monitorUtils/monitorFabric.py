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

CGC Monitor fab script
start requires parameters, e.g., 
fab -f ./monitorFabric.py start:db=cgc43,event=test_event1


'''

from fabric.api import run, sudo, settings, env, cd, put, reboot, parallel
from fabric.contrib.files import exists
import logging


# set the host to 10.20.200.101
env.hosts = ['10.20.200.101']
env.user = 'cgc'
env.password = 'cat'

def isrunning():
    output = run('/usr/bin/pgrep runEvent', warn_only=True)
    if output is not None and len(output) > 0:
        retval = True
    else:
        retval = False
    output = run('reportSQL ss')
    return retval


def kill():
    #warn only will emit an warning message if the command returns a non-zero status
    run('stopMonitor', warn_only=True)

def start(db, event):
    run('nohup runEvent %s %s 2>nohup.log 1>nohup.log &' % (db, event), pty=False)
    
def resume(db, event):
    run('nohup continueEvent %s %s 2>nohup.log 1>nohup.log &' % (db, event), pty=False)
    
def stop():
    run('stopMonitor', warn_only=True)

@parallel
def clean():
    print('not implemented')

def restart(db, event):
    stop()
    start(db, event)


def main():
    logger = logging.getLogger('')



if __name__ == '__main__':
    main()
