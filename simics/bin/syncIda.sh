#!/bin/bash
#
# Use rsync to copy hits files for a program from a remote server (e.g., blade)
# to the local machine, e.g., where IDA runs.  Will also copy IDA/Ghidra artifacts such
# as functions and blocks from the IDA/Ghidra workstation to the server.
# Run from the RESIM_ROOT_PREFIX directory.
# Run this from the machine that runs IDA or Ghidra.  It assumes RESIM_IDA_DATA 
# and IDA_ANALYSIS paths exists on each.
# 
#
if [ -z "$RESIM_IDA_DATA" ]; then
    echo "RESIM_IDA_DATA not defined."
    exit
fi
if [ -z "$IDA_ANALYSIS" ]; then
    echo "IDA_ANALYSIS not defined."
    exit
fi
if [ $# -lt 2 ] || [ $1 = "-h" ]; then
    echo "syncIda.sh <program> <server> [user]"
    echo "provide the optional user if id on remote differs from local."
    echo "Run from the RESIM_ROOT_PREFIX directory on the machine the runs IDA or Ghidra."
    echo "This will copy hits files (if any) from RESIM_IDA_DATA on the RESim server to the IDA/Ghidra workstation."
    echo "Those files are relative to the RESIM_IDA_DIR on each."
    echo "This will also copy artifacts such as function and blocks files from the IDA/Ghidra workstation to"
    echo "the server, but only if the server's IDA_ANALYIS path is not on an NSF server."
    exit
fi
if [ -f $1 ]; then
    program=$1
else
    echo "No program at ./$1, try exec_dict.json"
    program=./$(findProgram.py $1)
    if [ ! -f $program ]; then
        echo "No program at $program"
        exit
    fi
fi
program_base="$(basename -- $program)"
program_parent="$(dirname -- $program)"
#echo "parent is $program_parent"
here="$(pwd)"
root_dir="$(basename --  $here)"
root_dirname="$(dirname -- $here)"
root_parent="$(basename -- $root_dirname)"
#echo "the root_dir is $root_dir"
#echo "the root_dir parent is is $root_parent"
remote=$2
if [ $# -eq 3 ]; then
    user=$3@
else
    user=""
fi
#
# Copy hits files if any
#
remote_ida=$( ssh $user$remote "source \$HOME/.resimrc; echo \$RESIM_IDA_DATA" )
if [ -z "$remote_ida" ];then
           echo "The $remote server needs a ~/.resimrc file containing the RESim env variables that may be in your ~/.bashrc file"
           exit 1
fi
#echo "remote_ida is $remote_ida"
remote_program=$remote_ida/$root_parent/$root_dir/$program
parent="$(dirname "$remote_program")"
has_hits=$( ssh $user$remote "ls $remote_program*.hits" )
#echo "has_hits is $has_hits"
if [[ -z "$has_hits" ]]; then
    echo "No hits files on server, do not try to sync them."
else
    echo "Command is rsync -avh $user$remote:$remote_program*.hits $RESIM_IDA_DATA/$root_parent/$root_dir/$program_parent/"
    rsync -avh $user$remote:$remote_program*.hits $RESIM_IDA_DATA/$root_parent/$root_dir/$program_parent/
fi

#
#  Now copy analysis
#

analysis_dir=$IDA_ANALYSIS/$root_parent/$root_dir/$program_parent/
#echo "analysis_dir is $analysis_dir"
remote_analysis=$( ssh $user$remote "source \$HOME/.resimrc; echo \$IDA_ANALYSIS" )
#echo "remote_analysis is $remote_analysis"
remote_program=$remote_analysis/$root_parent/$root_dir/$program_parent/

file_type=$( ssh $user$remote "df $remote_program -TP | tail -n -1 | awk '{print \$2}'" )
#echo "file_type is $file_type"
if [[ $file_type == nfs* ]]; then
    echo "Remote is NSF, assume no need to synch analyisis artifacts."
else
    echo "remote program is $remote_program"
    ssh $user$remote "mkdir -p $remote_program"
    rsync -avh $analysis_dir $usr$remote:$remote_program
fi
