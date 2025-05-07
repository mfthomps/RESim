#!/bin/bash
#
# Generate new states by consuming inputs found by previous fuzzing sessions, and
# then fuzz from those new states.  This script is to be run iteratively, commencing
# after the initial progressive_fuzz.sh script.  The first run should not define
# the state_id parameter. Subsequent iteration state_ids will depend on earlier iterations.
#
# Calling script must export the following:
#     starting_ini : Name of starting ini file
#     commence : optional value for prepInject commence
#     FD : FD for prepInject
#     fuzz_timeout : timeout for fuzzing
#     program : program name
#     num_clones : number of fuzzing clones to create
#     state_id : optional state identifier string to pass to find_new_states.py
#                If not defined, then states found from the initial run of
#                progressive_fuzz.sh are used.
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
# crudely grab every queue file that maybe advanced state and add it to auto seeds
new_seeds=$(find_new_states.py -q -r)
mkdir -p ./auto_seeds
while IFS= read -r full_line ; do 
    #echo "full_line is $full_line"
    if [ "$full_line" == *"No paths"* ]; then
        continue
    fi
    line=$(echo $full_line | awk '{$1=$1;print}')
    #echo "line is $line"
    ws=$(echo $line | awk '{print $1}')
    ws_state=${ws:8}
    cover_file=$(echo $line | awk '{print $2}')
    qfile="${cover_file/coverage/queue}"
    echo "qfile is $qfile"
    new_qfile=$(basename -- $qfile)
    new_qfile+=$ws_state
    if [ ! -f auto_seeds/$new_qfile ]; then
        cp $qfile auto_seeds/$new_qfile
    fi
done <<< "$new_seeds"
# Get queue files that appear to reach new states.
# If state_id not defined, then get queue file found by the progressive_fuzz.sh
# script.
if [ -z "$state_id" ]; then
    result=$(find_new_states.py -q)
else
    echo "Using state_id $state_id"
    result=$(find_new_states.py -q -i $state_id)
fi
new_index=0
#
# Use each queue file to advance the state, and then fuzz from there.
#
# output results from find_new_states.py are formatted "workspace cover_file"
while IFS= read -r line ; do 
    ws=$(echo $line | awk '{print $1}')
    if [ -z "$ws" ]; then
        continue
    fi
    cover_file=$(echo $line | awk '{print $2}')
    qfile="${cover_file/coverage/queue}"
    echo "ws is $ws"
    # get index series starting with original unique index
    original_unique_index=${ws:8}
    echo "original_unique_index is $original_unique_index"
    echo "qfile is $qfile"
    # use the next state reached by consuming queue file named by index in unique list followed by subsequent index values
    mod_ini.sh $starting_ini next_state_$original_unique_index
    starting_ini=tmp.ini 
    index=$original_unique_index
    index+="_"
    index+=$new_index
    echo "index now $index"
    new_index=$((new_index + 1))
    starting_ws=$ws
    #echo " would: advance_and_fuzz $qfile $starting_ini $index $commence $FD $count $num_clones $program $starting_ws"
    advance_and_fuzz $qfile $starting_ini $index $commence $FD $count $num_clones $program $starting_ws
    cd $here
done <<< "$result"
