#
# Called by progressive_fuzz.sh to create a new state and then fuzz from that
#
advance_and_fuzz(){
    qfile=$1
    starting_ini=$2
    index=$3
    commence=$4
    FD=$5
    count=$6
    num_clones=$7
    program=$8
    starting_ws=$9
    echo "Will ingest queue file $qfile"
    #  Create a next state snapshot from injest of qfile
    next_state.sh $starting_ini next_state_$index $qfile $FD
    if [ ! -d next_state_$index ]; then
        echo "Failed to create snapshot next_state_$index"
        exit 1
    fi
    ##  Temporary ini file to run from new state
    mod_ini.sh $starting_ini next_state_$index
    ##  Creates prep inject snapshot
    if [ "$commence" != "NONE" ] && [ ! -z "$commence" ]; then
        echo "Run next_prep_commence.sh"
        next_prep_commence.sh tmp.ini $FD $commence next_prep_$index
    else
        echo "Run next_prep.sh"
        next_prep.sh tmp.ini $FD $count next_prep_$index
    fi
    mod_ini.sh $starting_ini next_prep_$index
    #  Create workspace for fuzzing this prep inject
    echo "run: autoclone.sh next_ws_$index $num_clones $qfile" 
    autoclone.sh next_ws_$index $num_clones $qfile || exit
    touch .watchdog_run
    autofuzz.sh next_ws_$index $program $fuzz_timeout || exit
    echo "Back from autofuzz.sh"
    #diffCoverage.py $starting_ws next_ws_$index
}
