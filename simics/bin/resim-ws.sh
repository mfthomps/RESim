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
# Use a link because simics agent downloads only from workspace
ln -s $RESIM_DIR/simics/bin/driver-server.py 
ln -s $RESIM_DIR/simics/driver_services
if [ "$1" == "-e" ]; then
#
#   Examples
#
    cp $RESIM_DIR/simics/examples/cadet/* .
fi
here=`pwd`
#if [ ! -d ./targets/qsp-x86 ]; then
if [ ! -d ./targets/x58-ich10 ]; then
#
#   Configure for use with Free Simics
#
    echo "Configuring for use with free Simics7"
    $RESIM_DIR/simics/bin/free-ws.sh
else
    cd targets/x58-ich10
    ln -s $RESIM_DIR/simics/simicsScripts/targets/x58-ich10/images
fi
echo "Workspace setup at $here."
