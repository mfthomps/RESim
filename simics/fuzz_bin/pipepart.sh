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
# Name of starting ini file
starting_ini=ecdis.ini
# value for prepInject commence
commence="AAAAAA"
# FD for prepInject
FD=0x6a0
# timeout for fuzzing
fuzz_timeout=80
# program name
program=Decider2.1.0.1
# number of fuzzing clones to create
num_clones=6
here=$(pwd)
# This target name, which matches afl output directory
starting_ws=$(basename -- "$here")
max_index=$(listUnique.py $starting_ws | tail -n 1 | awk '{print $1}')
# Index into the unique queue file list
index=0
for ((index=0; index<=$max_index; index++)); do

    # Get the queue file for this index
    qfile=$(getQueueFromIndex.py $starting_ws $index)
    if [ -z "$qfile" ]; then
        echo "Failed to find queue file for index $index"
        exit 1
    fi
    echo "Will ingest queue file $qfile"
    #  Create a next state snapshot from injest of qfile
    next_state.sh $starting_ini next_state_$index $qfile
    if [ ! -d next_state_$index ]; then
        echo "Failed to create snapshot next_state_$index"
        exit 1
    fi
    ##  Temporary ini file to run from new state
    mod_ini.sh next_state_$index
    ##  Creates prep inject snapshot
    if [ ! -z "$commence" ]; then
        echo "Run next_prep_commence.sh"
        next_prep_commence.sh tmp.ini $FD $commence next_prep_$index
    else
        echo "Run next_prep.sh"
        next_prep.sh tmp.ini $FD $count next_prep_$index
    fi
    mod_ini.sh next_prep_$index
    #  Create workspace for fuzzing this prep inject
    echo "run: autoclone.sh next_ws_$index $num_clones $qfile" 
    autoclone.sh next_ws_$index $num_clones $qfile || exit
    touch .watchdog_run
    autofuzz.sh next_ws_$index $program $fuzz_timeout || exit
    diffCoverage.py $starting_ws next_ws_$index
    cd $here
done
