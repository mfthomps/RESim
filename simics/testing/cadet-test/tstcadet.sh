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
cp $WS/authorized_keys .
cp $RESIM_DIR/simics/examples/cadet/* .
cp $TD/*.simics .
cp $TD/*.ini .
cp $TD/*.param .
cp $TD/*.sh .
cp $TD/*.directive .
cp $TD/*.io .
cp $TD/client.py .

resim cadet_driver.ini -c test_debug.simics
sed -i '/RESIM_TARGET/a RUN_FROM_SNAP=cadet' cadet_driver.ini
resim cadet_driver.ini -c test_rop.simics
./checkROP.sh || exit
resim cadet_driver.ini -c test_prep.simics
./checkPrep.sh || exit
sed -i 's/RUN_FROM_SNAP=cadet/RUN_FROM_SNAP=cadetread/' cadet_driver.ini
resim cadet_driver.ini -c test_track.simics
./checkTrack.sh || exit
./testAFL.sh || exit
./testPlay.sh || exit
./testDedupe.sh || exit
./testRunTrack.sh || exit
