#!/bin/bash
rop_result=$( grep "ROP eip" logs/monitors/resim.log )
if [[ -z "$rop_result" ]]; then
    echo "cadet test failed to detect ROP"
    exit 1
else
    rev_result=$( grep "while writing 0x75 to 0x" logs/monitors/resim.log )
    if [[ -z "$rev_result" ]]; then
        echo "cadet test failed to reverse to kernel write"
        exit 1
    else
        echo "cadet test passed"
    fi
fi
echo "DONE"
