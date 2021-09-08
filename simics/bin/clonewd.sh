#!/bin/bash
#
# Create N clones of the current simics workspace
# as subdirectories named resim1, resim2...
#
if [ "$#" -ne 1 ]; then
    echo "clonews.sh count"
    echo "   count is the number of clones to create as subdirectories to the workspace"
    exit
fi
here=$( pwd )
files=$( find . -maxdepth 1 -type f )
dirs=$( find . -maxdepth 1 -type d )
count=$1
for (( i=1; i<=$count; i++ )); do
    newdir="resim_$i"
    mkdir $newdir
    cd $newdir
    for f in $files; do
        target="$(basename -- $f)"
        ln -s ../$target
    done
    for d in $dirs; do
        target="$(basename -- $d)"
        if [ $target != "logs" ] && [ $target != "." ]; then
            echo "target is $target"
            ln -s ../$target
        fi
    done
    cd $here
done
