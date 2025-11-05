#!/bin/bash
move_pickle(){
    plist=$(ls $1/*.pickle)
    for p in $plist; do
        echo $p
        mv $p $2/
    done

    dlist=$(ls -d $1/*/)
    for d in $dlist; do
        echo $d
        mv $d $2/
    done
}
copy_pickle(){
    plist=$(ls $1/*.pickle)
    for p in $plist; do
        echo $p
        cp -aR $p $2/
    done

    dlist=$(ls -d $1/*/)
    for d in $dlist; do
        echo $d
        cp -aR $d $2/
    done
}
if [ "$#" -ne 2 ]; then
    echo "ckptMerge.sh src dest"
    echo "   Use Simics checkpoint-merge, but first remove pickles and then restore them."
    exit
fi
src=$1
dst=$2
if [ -d "merge_tmp" ]; then
    echo "Found a merge_tmp, must be removed"
    exit 1
fi
mkdir merge_tmp
move_pickle $1 merge_tmp
./bin/checkpoint-merge -c $1 $2
move_pickle merge_tmp $1
copy_pickle $1 $2
rmdir merge_tmp
