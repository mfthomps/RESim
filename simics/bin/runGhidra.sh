#!/bin/bash
#
# Run this from the target application root directory per the RESim ini file.
#
if [ -z "$RESIM_DIR" ]; then
    echo "RESIM_DIR not defined."
    exit
fi
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    echo "GHIDRA_INSTALL_DIR not defined."
    exit
fi
export target_root="$(pwd)"
echo "target_root is $target_root.  Your target binary should be relative to that diretory."
ghidra_parent=$(dirname "$GHIDRA_INSTALL_DIR")
cd $ghidra_parent
pwd
./ghidraRun

