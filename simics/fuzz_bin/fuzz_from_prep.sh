#!/bin/bash
#
# Run AFL on a prep inject snapshot; first create workspace and populate seeds
#
ws_name=$1
from_ws=$2
snapshot=$3
cd ../
mkdir $ws_name || exit
cd $ws_name
resim-ws.sh

