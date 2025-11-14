#!/bin/bash
#
# automated test of RESim using cadet01 sample.  
# Covers: debugProc, ROP detection, reverseToSP, prepInjectWatch, injectIO with kernel buffer.
#
if [[ -z "$RESIM_DIR" ]]; then
    echo "RESIM_DIR not defined."
    exit
fi

echo "Running cadet test using Simics $SIMDIR"

TD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
rm -fr cadet-tst
mkdir cadet-tst
cd cadet-tst
resim-ws.sh
export WS=$RESIM_DIR/simics/workspace
echo "ws is $WS"
cp $WS/ubuntu_driver.ini $WS/ubuntu.param $WS/driver-script.sh $WS/mapdriver.simics $WS/authorized_keys .


#sed -i 's/mapdriver.simics/cadet.simics/' ubuntu_driver.ini
sed -i '/OS_TYPE/a AFL_STOP_ON_READ=TRUE' ubuntu_driver.ini
#echo "INTERACT_SCRIPT=teecadet.simics" >> ubuntu_driver.ini

cp $TD/*.simics .
cp $TD/*.sh .
cp $TD/*.directive .
cp $TD/*.io .
cp $TD/client.py .

resim ubuntu_driver.ini -c test_debug.simics
sed -i '/RESIM_TARGET/a RUN_FROM_SNAP=cadet' ubuntu_driver.ini
resim ubuntu_driver.ini -c test_rop.simics
./checkROP.sh || exit
resim ubuntu_driver.ini -c test_prep.simics
./checkPrep.sh || exit
sed -i 's/RUN_FROM_SNAP=cadet/RUN_FROM_SNAP=cadetread/' ubuntu_driver.ini
resim ubuntu_driver.ini -c test_track.simics
./checkTrack.sh
./testAFL.sh 
./testPlay.sh || exit
./testDedupe.sh || exit
./testRunTrack.sh || exit
