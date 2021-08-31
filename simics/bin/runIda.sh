#
# Start IDA for a given target, setting a hotkey of "R" to attach to 
# the debugger and load the RESim IDA Client plugin. 
#
# The target file (to be disassembled) must be the first argument.
# Options for the 2nd argument include:
#     color -- reset IDA graph block colors and then color per the program hits files
#
if [ -z "$IDA_DIR" ]; then
    echo "IDA_DIR not defined."
    exit
fi
if [ -z "$RESIM_DIR" ]; then
    echo "RESIM_DIR not defined."
    exit
fi
if [[ ! -f "$IDA_DIR/idc/runRESim.idc" ]]; then
    echo "Copying runRESim.idc to the IDA directory at $IDA_DIR/idc"
    cp $RESIM_DIR/simics/ida/runRESim.idc $IDA_DIR/idc
fi
idacmd=$IDA_DIR/ida
target=$1
shift 1
$idacmd -S"$RESIM_DIR/simics/ida/RESimHotKey.idc $@" $target
