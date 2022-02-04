#!/bin/bash
#
# Run the runAFL program locally.  Intended to be started as an ssh command.
# Pass in the workspace path and the target ini file.
#
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
if [ ! -d $target ]; then
    echo "No directory at $target, exiting."
    exit 1
fi
cd $target
source $HOME/.resimrc
PATH=$RESIM_DIR/simics/bin:$PATH
echo "now xrunAFL at target $target"
echo "$RESIM_DIR/simics/bin/runAFL -r $ini $@ &"
$RESIM_DIR/simics/bin/runAFL -r $ini $@ &

