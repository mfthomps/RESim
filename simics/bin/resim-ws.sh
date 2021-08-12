#!/bin/bash
#
# Create a Simics workspace for use with RESim
# Link to this file from someplace in your path, e.g.,
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
cp $RESIM_DIR/simics/workspace/monitor6.sh monitor.sh
here=`pwd`
echo "Workspace setup at $here."
