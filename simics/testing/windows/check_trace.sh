#!/bin/bash
result=$(grep bow logs/syscall*)
if [ -z "$result" ]; then
    echo "failed to find bow wow entry in trace"
    exit 1
fi
echo "Trace test passed."
