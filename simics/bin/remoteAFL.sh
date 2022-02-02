#!/bin/bash
echo $@
if [ "$#" -ne 2 ] || [ "$1" = "-h" ]; then
    echo "remoteAFL <workspace> <target ini>"
    echo "   Start the runAFL from the given target workspace (full path) with the given target ini file"
    exit
fi
target=$1
shift 1
ini=$1
shift 1
cd $target
source $HOME/.resimrc
PATH=$RESIM_DIR/simics/bin:$PATH
echo "now xrunAFL at target $target"
echo "$RESIM_DIR/simics/bin/runAFL -r $ini $@ &"
$RESIM_DIR/simics/bin/runAFL -r $ini $@ &

