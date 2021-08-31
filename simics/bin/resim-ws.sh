#!/bin/bash
#
# Create a Simics workspace for use with RESim
# Add thi simics/bin to your path or link to this file from someplace in your path, e.g.,
#  ln -s $RESIM_DIR/simics/bin/resim-ws.sh $HOME/bin/resim-ws.sh
#
if [[ -z "$SIMDIR" ]]; then
   echo "SIMDIR not defined"
   exit
fi
if [[ -z "$RESIM_DIR" ]]; then
   echo "RESIM_DIR not defined"
   exit
fi
$SIMDIR/bin/project-setup  || exit
cp $RESIM_DIR/simics/workspace/mytarget.ini .
cp $RESIM_DIR/simics/workspace/driver-script.sh .
cp $RESIM_DIR/simics/workspace/ubuntu.param .
cp $RESIM_DIR/simics/workspace/ubuntu.ini .
here=`pwd`
echo "Workspace setup at $here."
