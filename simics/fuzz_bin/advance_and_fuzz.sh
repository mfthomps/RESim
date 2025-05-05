#
# Called by progressive_fuzz.sh to create a new state and then fuzz from that
#
advance_and_fuzz(){
    qfile=$1
    starting_ini=$2
    state_id=$3
    commence=$4
    FD=$5
    count=$6
    num_clones=$7
    program=$8
    starting_ws=$9
    if [ ! -d next_state_$state_id ]; then
        echo "Will ingest queue file $qfile"
        #  Create a next state snapshot from injest of qfile
        next_state.sh $starting_ini next_state_$state_id $qfile $FD
        if [ ! -d next_state_$state_id ]; then
            echo "Failed to create snapshot next_state_$state_id"
            exit 1
        fi
    else
        echo "Found existing snapshot for next_state_$state_id"
    fi
    if [ ! -d next_prep_$state_id ]; then
        ##  Temporary ini file to run from new state
        mod_ini.sh $starting_ini next_state_$state_id
        ##  Creates prep inject snapshot
        if [ "$commence" != "NONE" ] && [ ! -z "$commence" ]; then
            echo "Run next_prep_commence.sh"
            next_prep_commence.sh tmp.ini $FD $commence next_prep_$state_id
        else
            echo "Run next_prep.sh"
            next_prep.sh tmp.ini $FD $count next_prep_$state_id
        fi
    fi
    ws_name=next_ws_$state_id
    newdir=auto_ws/$ws_name
    if [ -d $newdir ] && [ ! -f ~/afl/output/$ws_name/$ws_name.unique ]; then
        echo "Assuming workspace $ws_name did not complete fuzzing.  Delete it and fuzzing results."
        rm -fr $newdir
        rm -fr ~/afl/output/$ws_name
    fi
    if [ ! -f ~/afl/output/$ws_name/$ws_name.unique ]; then
        mod_ini.sh $starting_ini next_prep_$state_id
        #  Create workspace for fuzzing this prep inject and populate its seeds
        echo "run: autoclone.sh next_ws_$state_id $num_clones $qfile" 
        autoclone.sh $state_id $num_clones $qfile || exit
        touch .watchdog_run
        # fuzz it
        autofuzz.sh next_ws_$state_id $program $fuzz_timeout || exit
        echo "Back from autofuzz.sh"
        #diffCoverage.py $starting_ws next_ws_$state_id
    else
        echo "Found existing fuzz/coverage results; skip fuzzing for $ws_name"
    fi
}
