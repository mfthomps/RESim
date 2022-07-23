#!/bin/bash
mark_result=$( grep "len of mark_list now 141" logs/monitors/resim.log )
if [[ -z "$mark_result" ]]; then
    echo "cadet test failed to trackio"
    exit 1
fi
echo "passed trackio"
