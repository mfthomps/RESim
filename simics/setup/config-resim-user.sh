#!/bin/bash
#
# Configure a user account to use RESim, creates a ~git/RESim and a  ~/workspace for
# running RESim.
#
# add env to bashrc
export RESIM_DIR=~/git/RESim
cat >> ~/.bashrc <<- EOM
export RESIM_DIR=~/git/RESim
export SIMDIR=/mnt/simics/simics-4.8/simics-4.8.170
EOM
# add RESim PATH to profile
cat >> ~/.profile <<- EOM
PATH=$RESIM_DIR/simics/bin:$PATH
EOM
# clone RESim repo
mkdir ~/git
cd ~/git
git clone https://github.com/mfthomps/RESim.git
# create first workspace
mkdir ~/workspace
cd ~/workspace
$RESIM_DIR/simics/bin/resim-ws.sh
echo "Use bash to get a new shell with env variables."

