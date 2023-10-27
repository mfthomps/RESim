#!/bin/bash
#
# Parse trace logs (output from cgc.saveTraces) and generate summeries.
# Uses the RESIM_DIR/postscripts scripts to do this.
# Run this from a log directory after running traceAll and saveTraces.
#
here=$(pwd)
if [[ -z "$RESIM_DIR" ]]; then
    echo "RESIM_DIR not defined."
    exit
fi
if [[ ! -f binder.json ]]; then
    echo "Must be run from a directory having traceAll artifacts, e.g., from cgc.saveTraces.  No binder.json found."
    exit
fi
cd $RESIM_DIR/postscripts
./genRpt.sh $here
echo "Done"
