#!/bin/bash
#
# Create clone of the current simics workspace and put it under auto_ws/$ws_name
#
if [ "$#" -ne 3 ]; then
    echo "autoclone.sh ws_name quantity qfile"
    echo "   creates a clone under auto_ws, and then (quantity) fuzzing clones under that"
    echo "   And copy unique queue files of current workspace as seeds for new workspace"
    echo "   The qfile parameter is simply used to document the providence of the new workspace."
    exit
fi
ws_name=$1
quantity=$2
source_qfile=$3
newdir=auto_ws/$ws_name
echo "new dir is $newdir"
mkdir -p $newdir || exit
here=$( pwd )
source_ws=$(basename -- $here)
files=$( find . -maxdepth 1 -type f )
dirs=$( find . -maxdepth 1 -type d )
links=$( find . -maxdepth 1 -type l )
cd $newdir || exit
echo "Workspace derived from workspace $source_ws consumption of queue file $source_qfile"
for f in $files; do
    target="$(basename -- $f)"
    ln -s ../../$target
done
for d in $dirs; do
    target="$(basename -- $d)"
    if [ $target != "logs" ] && [ $target != "." ] && [ $target != "auto_ws" ]; then
        echo "target is $target"
        ln -s ../../$target
    fi
done
for l in $links; do
    target="$(basename -- $l)"
    if [ $target != "logs" ] && [ $target != "." ] && [ $target != "doc" ] && [[ $target != resim_* ]]; then
        echo "target is $target"
        ln -s ../../$target
    fi
done
cycleSeeds.py -t $source_ws
clonewd.sh $quantity
cd $here
