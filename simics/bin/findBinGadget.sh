#!/bin/bash
#
# Search binary files listed in static.list
# for a binary sequence from assembling
# input instructions separated by simicolons.
#
tfile=/tmp/tmp.asm
# write the assembly code to a file
echo "org 0" > $tfile
echo "bits 32" >> $tfile
IFS=';' read -ra ADDR <<< "$1"
for i in "${ADDR[@]}"; do
  echo $i >> $tfile
done
# assemble the code into a.out
asm.sh $tfile
bstring=$(hexdump a.out -ve '1/1 "%.2x"')
echo "bytesInStatic.py ecdis.ini $bstring static.list"
bytesInStatic.py ecdis.ini $bstring static.list
