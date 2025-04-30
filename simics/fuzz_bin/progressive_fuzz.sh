#!/bin/bash
#
# for each queue file (unique_index)
#    drive it with queue file, mapping coverage and writeConfig as state_(unique_index) 
#    from state_(unique_index) snapshot, drive with A's and prepInject to prep_(unique_index) 
#    create workspace ws_prep_(unique_index)
#    cd new workspace sym link to prep_(unique_index) snapshot
#    add all queue files as seeds
#    runAFL until no new paths for X minutes
#    runPlay
#    dedupe
#    identify new queue files that result in new hits
#
# Calling script must export the following:
#     starting_ini : Name of starting ini file
#     commence : optional value for prepInject commence
#     FD : FD for prepInject
#     fuzz_timeout : timeout for fuzzing
#     program : program name
#     num_clones : number of fuzzing clones to create
source $RESIM_DIR/simics/fuzz_bin/advance_and_fuzz.sh
if [ -z "$starting_ini" ] || [ -z "$FD" ] || [ -z "$fuzz_timeout" ] || [ -z "$program" ] || [ -z "$num_clones" ]; then
    echo "Must define starting_ini, FD, fuzz_timeout, program and num_clones"
    exit
fi
if [ ! -z "$count" ] && [ ! -z "$commence" ]; then
    echo "Cannot define both count and commence"
    exit
fi
if [ -z "$count" ] && [ -z "$commence" ]; then 
    echo "Assuming count of 1"
    count=1
    commence="NONE"
fi
if [ -z "$commence" ]; then
    commence="NONE"
fi
if [ -z "$count" ]; then
    count="NONE"
fi

here=$(pwd)
# This target name, which matches afl output directory
starting_ws=$(basename -- "$here")
max_index=$(listUnique.py $starting_ws | tail -n 1 | awk '{print $1}')
# Index into the unique queue file list
index=0
#
# create states derived from ingest of each "unqiue" queue file and fuzz from each
#
for ((index=0; index<=$max_index; index++)); do

    # Get the queue file for this index
    qfile=$(getQueueFromIndex.py $starting_ws $index)
    if [ -z "$qfile" ]; then
        echo "Failed to find queue file for index $index"
        exit 1
    fi
    advance_and_fuzz $qfile $starting_ini $index $commence $FD $count $num_clones $program $starting_ws
    cd $here
done
