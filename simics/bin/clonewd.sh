#!/bin/bash
#
# Create N clones of the current simics workspace
# as subdirectories named resim_1, resim_2...
# for use in running parallel instances of RESim/AFL.
#
if [ "$#" -ne 1 ] || [ "$1" == "-h" ]; then
    echo "clonews.sh count"
    echo "Create N clones of the current simics workspace"
    echo "as subdirectories named resim_1, resim_2..."
    echo "for use in running parallel instances of RESim/AFL."
    echo "   Count is the number of clones to create as subdirectories to the workspace"
    exit
fi
here=$( pwd )
files=$( find . -maxdepth 1 -type f )
dirs=$( find . -maxdepth 1 -type d )
links=$( find . -maxdepth 1 -type l )
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
            #echo "target is $target"
            ln -s ../$target
        fi
    done
    for l in $links; do
        target="$(basename -- $l)"
        if [ $target != "logs" ] && [ $target != "." ] && [ $target != "doc" ]; then
            #echo "target is $target"
            ln -s ../$target
        fi
    done
    cd $here
done
echo "Created $count clone directories with name resim_1 - resim_$count"
