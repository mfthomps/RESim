#!/bin/bash
:<<'END_COMMENT'
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
END_COMMENT

#
# collect scripts and data from the development system and put them into the /mnt/vmLib
# where the slaves can find them during their installation process and during their 
# bootstrap updates
# Optional vmLib extension, e.g., "2" to put tarball on different vmLib
#
#  Error on the side of including everying, so an arbitrary slave can become a master
#
ss=simics/simicsScripts
si=simics/slaveInstall
sm=simics/masterInstall
sida=simics/ida
sr=simics/rebuild
sl=simics/licenses
share=/mnt/vmLib$1/cgcForensicsRepo
here=`pwd`
src=/mnt/cgcsvn/cgc/users/mft
cd $src
#
#  NOTE we don't copy default.cfg because we don't want to override changes made on masters
#
#tar --exclude=.svn -cvf monitor.tar $ss/*.py $ss/*.sh zk/py/*.py zk/py/*.sh zk/py/*.xml zk/msc/* $ss/targets $si/* $ss/debian.params $ss/*.sh $sr/*.py $sr/*.sh zk/demoRepo/*.py zk/demoRepo/*.sh zk/demoRepo/unstack zk/zkShell/* zk/zkMaster/* $sm/* zk/sql/* zk/fdbRepo/* zk/pgRepo/* $sida/*  
#tar --exclude=.svn -cvf monitor.tar  zk/py/*.xml zk/msc/* $ss/targets $ss/*.sh $ss/tests $si/* $ss/debian.params $sr/*.py $sr/*.sh zk/demoRepo/*.py zk/demoRepo/*.sh zk/demoRepo/unstack $sm/* zk/sql/* $sida/* zk/pgRepo/*.sh zk/py/tests zk/pgRepo/tests
mkdir -p $share
#mv monitor.tar $share/
mkdir -p $share/slaveLinuxConfig
mkdir -p $share/licenses
cp $si/hosts-add $si/sources.list $si/fstab-add $sm/configureMaster.sh $share/slaveLinuxConfig/
cp $sl/*.lic $sl/*.txt $share/licenses/

# NOTE we get the simics modules from workspace0 on devel system
cd /mnt/simics/simicsWorkspace0
tar -cvf $share/simicsModules.tar linux64
cd $here
echo "copied monitor tar to $share"
