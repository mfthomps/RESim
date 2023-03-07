#!/bin/bash
#
# use rsync to copy ida_data files for a program from a remove server (e.g., blade)
# to the local machine, e.g., where IDA runs.
#
if [ -z "$RESIM_IDA_DATA" ]; then
    echo "RESIM_IDA_DATA not defined."
    exit
fi
if [ $# -lt 2 ] || [ $1 = "-h" ]; then
    echo "syncIda.sh <target> <server> [user]"
    echo "provide the optional user if id on remote differs from local."
    exit
fi
target=$1
target_base="$(basename -- $target)"
remote=$2
if [ $# -eq 3 ]; then
    user=$3@
else
    user=""
fi
remote_ida=$( ssh $user$remote "source $HOME/.resimrc;mkdir -p \$RESIM_IDA_DATA/$target_base; echo \$RESIM_IDA_DATA" )
if [ -z "$remote_ida" ];then
           echo "The $remote server needs a ~/.resimrc file containing the RESim env variables that may be in your ~/.bashrc file"
           exit 1
fi
rsync -avh $user$remote:$remote_ida/$target_base/*.hits $RESIM_IDA_DATA/$target_base/

