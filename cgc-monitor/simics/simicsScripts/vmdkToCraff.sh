#!/bin/bash
show_usage() {
   echo "vmdkToCraff.sh vmdk"
   echo "    Create a Simics craff bootable image from a given vmdk file"
}
if [ $# -lt 1 ]
then
    show_usage
    exit 1
fi

if [ $1 -nt traceTarget.craff ]; then
    VBoxManage internalcommands converthd -srcformat vmdk -dstformat raw $1 traceTarget.img
    bin/craff traceTarget.img -o traceTarget.craff
else
    echo "already have a craff for $1?"
fi
