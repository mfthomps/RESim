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
me=`whoami`
ida_bin=`which idaq`
lfile=cgc.llx
if [ ! -z $ida_bin ]; then
   echo $ida_bin
   ida_path=$(dirname "${ida_bin}")
   echo "found in path, using idaq from  $ida_path"
fi

if [ -z $ida_path ]; then
   me=`whoami`
   ida_bin=`find /home/$me/ida* -name idaq` 
   if [ ! -z "$ida_bin" ]; then
       ida_path=$(dirname "${ida_bin}")
       echo "idaq not in path, found under /home/$me, using idaq from $ida_path"
   fi
fi
if [ -z $ida_path ]; then
   ida_bin=`find /Applications/IDA* -name idaq`
   if [ ! -z "$ida_bin" ]; then
       ida_path=$(dirname "${ida_bin}")
       echo "idaq not in path, found under /Applications, using idaq from $ida_path"
   fi
fi
idaq=$ida_path/idaq
if [ -z "$idaq" ]; then
   echo "no idaq path, fixme (startIda.sh)"
   exit 1 
fi
loader=$ida_path/loaders/$lfile
if [ ! -f "$loader" ]; then
   if [ -f /usr/share/cgc-monitor/$lfile ]; then
       cp /usr/share/cgc-monitor/$lfile "$loader"
   else
       cp ../simics/ida/$lfile "$loader"
   fi
   echo "copied cgc loader plugin to $loader"
fi
file=$1
idb_file=$file
if [[ $file == *.rcb ]]; then
   idb_file=${file%.*}
fi
if [[ $file == *.pov ]]; then
   idb_file=${file%.*}
fi
echo starting Ida for $1
if [ ! -f $idb_file.idb ]; then
    echo "$idaq" -TCGC -B $file
    "$idaq" -TCGC -B $file
    echo "Done creating IDB file"
else
    echo "IDB file already exists"
fi
if [ -z "$2" ]; then
    echo "no parameters, use defaults"
    script="/mnt/cgcsvn/cgc/trunk/cgc-monitor/simics/ida/rev.py"
    if [ ! -f "$script" ]; then
        script="/Volumes/disk2/cgc/cgc/trunk/cgc-monitor/simics/ida/rev.py"
    fi
    port=9123
    ip='localhost'
else
    script=$2
    ip=$3
    instance=$4
    port=$5
fi
# see if we are running on a cgcMonitor box
echo "see if we are running on a cgcMonitor box"
PROC=$(ps aux | grep '[s]imics-common'  | grep -v tail | awk '{print $2}')
#if [ $? -eq 0 ]; then
if [ -z $PROC ]; then
   echo "not on monitor box, check for proxy"
   PROC=$(ps aux | grep 'ssh -p 2444'  | grep "$ip" | grep "$port")
   if [ ! $? -eq 0 ]; then
       echo "no gdb ssh tunnel for $ip:$port, make one"
       gdbSSHProxy.sh $ip $port & 
   fi
fi

#echo ip is $ip instance is $instance
echo "$idaq" -TCGC -A -rgdb@localhost:$port -S$script $idb_file.idb
#echo "$idaq" -TCGC -A -rgdb@localhost:$port $idb_file.idb
"$idaq" -TCGC -A -rgdb@localhost:$port -S$script $idb_file.idb
#"$idaq" -TCGC -A -rgdb@localhost:$port $idb_file.idb

#echo "$idaq" -TCGC -A $idb_file.idb
#"$idaq" -TCGC -A $idb_file.idb

