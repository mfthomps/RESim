#!/bin/bash
result=$(grep "6 b'Read 16" my_test.wm)
if [ -z "$result" ]; then
    echo "failed to find Read 16 at entry 6 in watch marks"
    exit 1
fi
echo "Track test passed."
