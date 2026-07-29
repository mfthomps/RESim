#!/bin/bash
# Assumes the cadetread checkpoint was created using prepInjectWatch
# create afl clone working directories
rm -fr $AFL_DATA/output/cadet-tst
mkdir -p $AFL_DATA/seeds/cadet-tst
echo "not-a-palidrome" > $AFL_DATA/seeds/cadet-tst/seed.io
rm -fr resim_*
clonewd.sh 5
runAFL cadet_driver.ini -b -s 300
list=$(ls ~/afl/output/cadet-tst/*_resim_*/crashes/*)
if [[ $list = *id:000* ]]; then
    echo "AFL passed, found crash"
else
    echo "AFL failed to find crash"
    exit 1
fi
