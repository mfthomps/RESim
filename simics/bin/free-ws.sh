#!/bin/bash
#
#  Add qsp packages needed to run the free Simics
#
if [[ -z "$SIMDIR" ]]; then
   echo "SIMDIR not defined"
   exit
fi
PDIR=$(realpath $SIMDIR/../)
qspcpu=$(ls -t $PDIR | grep -m1 qsp-cpu)
qspcpufull=$PDIR/$qspcpu
qspx86=$(ls -t $PDIR | grep -m1 qsp-x86)
qspx86full=$PDIR/$qspx86
qspclr=$(ls -t $PDIR | grep -m1 qsp-clear-linux)
qspclrfull=$PDIR/$qspclr
echo $qspcpufull >mylist
echo $qspx86full >>mylist
echo $qspclrfull >>mylist
./bin/project-setup  --package-list mylist || exit
echo "QSP x86 added to workspace"
if [ ! -d targets/x58-ich10 ]; then
    cd targets
    ln -s $RESIM_DIR/simics/simicsScripts/targets/x58-ich10
    echo "Link created for targets/x58-ich10"
fi
