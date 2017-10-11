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

./doMark.sh
zkdir=../../../trunk/cgc-monitor/zk
here=`pwd`
rm -fr /tmp/cgc-monitor
mkdir /tmp/cgc-monitor
mkdir /tmp/cgc-monitor/idaClient
cp * /tmp/cgc-monitor/idaClient/
mkdir /tmp/cgc-monitor/zk
cp -r $zkdir/monitorLibs /tmp/cgc-monitor/zk/
cp -r $zkdir/monitorUtils /tmp/cgc-monitor/zk/
mkdir /tmp/cgc-monitor/simics
cp -r ../simics/ida /tmp/cgc-monitor/simics/
cd /tmp
#tar -cvf $here/cgcMonitorClient.tar cgc-monitor --exclude=".svn"
tar -cvf $here/cgcMonitorClient.tar --exclude=".svn" cgc-monitor
gzip $here/cgcMonitorClient.tar
cp $here/cgcM*gz /tmp/
cd $here
