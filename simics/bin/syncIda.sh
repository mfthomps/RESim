#!/bin/bash
#
# use rsync to copy ida_data files for a program from a remote server (e.g., blade)
# to the local machine, e.g., where IDA runs.  Run from the RESIM_ROOT_PREFIX directory
#
if [ -z "$RESIM_IDA_DATA" ]; then
    echo "RESIM_IDA_DATA not defined."
    exit
fi
if [ $# -lt 2 ] || [ $1 = "-h" ]; then
    echo "syncIda.sh <program> <server> [user]"
    echo "provide the optional user if id on remote differs from local."
    echo "Run from the RESIM_ROOT_PREFIX directory"
    exit
fi
program=$1
program_base="$(basename -- $program)"
here="$(pwd)"
root_dir="$(basename --  $here)"
remote=$2
if [ $# -eq 3 ]; then
    user=$3@
else
    user=""
fi
remote_ida=$( ssh $user$remote "source \$HOME/.resimrc;mkdir -p \$RESIM_IDA_DATA/$root_dir/$program_base; echo \$RESIM_IDA_DATA" )
if [ -z "$remote_ida" ];then
           echo "The $remote server needs a ~/.resimrc file containing the RESim env variables that may be in your ~/.bashrc file"
           exit 1
fi
rsync -avh $user$remote:$remote_ida/$root_dir/$program_base/*.hits $RESIM_IDA_DATA/$root_dir/$program_base/

