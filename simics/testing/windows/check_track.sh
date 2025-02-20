#!/bin/bash
result=$(grep "5 b'printf" my_test.wm)
if [ -z "$result" ]; then
    echo "failed to find printf at entry 5 in watch marks"
    exit 1
fi
echo "Track test passed."
