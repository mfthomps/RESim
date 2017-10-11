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
if [[ $1 == CB* ]]; then
  comm=$1
  suffix="_MG"
  if [[ "$comm" == *_MG ]]; then
      echo "is mitigated"
      comm=${comm%$suffix}
      echo "comm now $comm"
  fi
      
  prefix=/mnt/vmLib/cgcForensicsRepo/CB-share/v2/CBs/$comm/author/$1
  scp hp1:$prefix/$1* /tmp/$1_01
  full_path=/tmp/$1_01
else
    prefix=/mftdata/cfe_snapshot/final-game/1470326433.800818.cgc-forensics
    full_path=$prefix/$1
    if [ ! -f $full_path ]; then
        scp mft-ref:$full_path /tmp/
        full_path=/tmp/$1
    fi
fi
file=$full_path
idb_file=$file
if [[ $file == *.rcb ]]; then
   idb_file=${file%.*}
fi
if [[ $file == *.pov ]]; then
   idb_file=${file%.*}
fi
echo starting Ida for $full_path
if [ ! -f $idb_file.idb ]; then
    echo "$idaq" -TCGC -B $file
    "$idaq" -TCGC -B $file
    echo "Done creating IDB file"
else
    echo "IDB file already exists"
fi
#echo ip is $ip instance is $instance
#script='/mftdata/cgcsvn/cgc/trunk/cgc-monitor/simics/ida/oneSig.py'
#echo "$idaq" -TCGC -S$script $idb_file.idb
#"$idaq" -TCGC -S$script $idb_file.idb
"$idaq" -TCGC $idb_file.idb
