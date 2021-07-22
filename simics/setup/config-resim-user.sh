#!/bin/bash
#
# Configure a user account to use RESim, creates a ~git/RESim and a  ~/workspace for
# running RESim.
#
#git config --global http.proxy http://webproxy:3128
#git config --global https.proxy https://webproxy:3128
cat >> ~/.bashrc <<- EOM
export RESIM=~/git/RESim
EOM
mkdir ~/git
cd ~/git
git clone https://github.com/mfthomps/RESim.git

mkdir ~/workspace
cd ~/workspace
/mnt/simics/simics-4.8/simics-4.8.170/bin/workspace-setup
cp ~/git/RESim/simics/workspace/* .
echo "Use bash to get a new shell with env variables."

