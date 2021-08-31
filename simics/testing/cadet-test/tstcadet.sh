#!/bin/bash
#
# automated test of RESim using cadet01 sample.  Not a detailed test,
# but does cover ROP detection.
#
if [[ -z "$RESIM_DIR" ]]; then
    echo "RESIM_DIR not defined."
    exit
fi
TD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
rm -fr cadet-tst
mkdir cadet-tst
cd cadet-tst
resim-ws.sh
export WS=$RESIM_DIR/simics/workspace
echo "ws is $WS"
cp $WS/cadet01 $WS/cadet01.funs $WS/ubuntu_driver.ini $WS/ubuntu.param $WS/driver-script.sh .

sed -i '/OS_TYPE=LINUX32/a INIT_SCRIPT=cadet.simics' ubuntu_driver.ini
echo "INTERACT_SCRIPT=teecadet.simics" >> ubuntu_driver.ini

cp $TD/*.simics .
cp $TD/findWindow.sh .
cp $TD/checkROP.sh .
# use ~/bin/set-title
set-title "cadet01-tst"

resim ubuntu_driver.ini
./checkROP.sh
