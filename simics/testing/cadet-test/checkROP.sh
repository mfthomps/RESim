#!/bin/bash
result=$( grep "ROP eip" logs/monitors/resim.log )
if [[ -z "$result" ]]; then
    echo "cadet test failed"
else
    echo "cadet test passed"
fi
echo "DONE"
