#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "clean_these_dirs state_id"
    exit
fi

rm -fr next_state_$1
rm -fr next_prep_$1
rm -fr auto_ws/next_ws_$1
rm -fr ~/afl/output/next_ws_$1
rm -fr ~/afl/seeds/next_ws_$1
echo "Removed all auto fuzz directories and AFL target files for state id $1"
