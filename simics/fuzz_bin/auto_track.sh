#!/bin/bash
#
#  Run runTrack on all auto-generated fuzzing workspaces that find_new_states.py reports as having new state.
#  No attempt is made for parallel execution beyond that provided by runTrack, i.e., only if a workspace has
#  multiple queue files.
#
result=$(find_new_states.py -q -r | awk '{print $1}' | uniq)
here=$(pwd)
for workspace in $result; do
    cd auto_ws/$workspace
    # modify the tmp.ini to use this workspace prep inject snapshot
    state_id=${workspace:8}
    snapshot=next_prep_$state_id
    mod_ini.sh tmp.ini $snapshot
    echo "runTrack for $workspace"
    runTrack tmp.ini -w $workspace
    while [ 1 ]; do
        running=$(ps aux | grep '[r]unTrack' | grep -v 'vi ' | awk '{print $2}')
        if [ ! -z "$running" ]; then
            sleep 10
        else
            break
        fi
        
   done
   echo "Done with $workspace"
   cd $here
done
echo "Done with auto_track.sh"
