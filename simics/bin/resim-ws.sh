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
if [ "$1" == "-h" ]; then
   echo "resim-ws.sh"
   echo "   Create a Simics workspace (project) directory and populate it with common RESim files."
   echo "   Use -e to populate the workspace with example ini files and example param files."
fi
$SIMDIR/bin/project-setup  || exit
cp $RESIM_DIR/simics/workspace/driver-script.sh .
cp $RESIM_DIR/simics/workspace/authorized_keys .
if [ "$1" == "-e" ]; then
#
#   Examples
#
    cp $RESIM_DIR/simics/workspace/mytarget.ini .
    cp $RESIM_DIR/simics/workspace/ubuntu_driver.ini .
    cp $RESIM_DIR/simics/workspace/client.py .
    cp $RESIM_DIR/simics/workspace/ubuntu.param .
    cp $RESIM_DIR/simics/workspace/clear-linux.ini .
    cp $RESIM_DIR/simics/workspace/clear64.param .
    cp $RESIM_DIR/simics/workspace/mapdriver.simics .
fi
here=`pwd`
echo "Workspace setup at $here."
if [ ! -d ./targets/qsp-x86 ]; then
#
#   Configure for use with Free Simics
#
    $RESIM_DIR/simics/bin/free-ws.sh
fi
