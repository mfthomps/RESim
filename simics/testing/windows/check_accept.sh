#!/bin/bash
result=$(grep "ACCEPT bind socket: 0x64 connect socket: 0x68" logs/monitors/resim.log)
if [ -z "$result" ]; then
    echo "failed to find ACCEPT entry in log"
    exit 1
fi
echo "Accept test passed."
