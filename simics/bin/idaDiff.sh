#
# Start IDA for a given program name
#
# The program file (to be disassembled) must be the first argument.
# The next 2 arguments are coverage files.
# Must be run from the RESIM_ROOT_PREFIX directory (per the init file)
#
if [ -z "$IDA_DIR" ]; then
    echo "IDA_DIR not defined."
    exit
fi
if [ -z "$RESIM_DIR" ]; then
    echo "RESIM_DIR not defined."
    exit
fi
if [ -z "$RESIM_IDA_DATA" ]; then
    echo "RESIM_IDA_DATA not defined."
    exit
fi
if [[ ! -f "$IDA_DIR/idc/runRESim.idc" ]]; then
    echo "Copying runRESim.idc to the IDA directory at $IDA_DIR/idc"
    cp $RESIM_DIR/simics/ida/runRESim.idc $IDA_DIR/idc
fi
idacmd=$IDA_DIR/ida
target=$1
target_base="$(basename -- $target)"
here="$(pwd)"
root_dir="$(basename --  $here)"
shift 1

target_path=$(realpath $target)
ida_db_path=$RESIM_IDA_DATA/$root_dir/$target_base/$target_base.idb
echo "target is $target"
echo "dbpath $ida_db_path"
remain="$@"
echo "remain is $remain"

if [[ -f $ida_db_path ]];then
    #$idacmd -S"$RESIM_DIR/simics/ida/RESimHotKey.idc $target_path $@" $ida_db_path
    $idacmd -S"$RESIM_DIR/simics/ida/diffBlocks.py $remain" $ida_db_path
else
    echo "No IDA db at $ida_db_path."
fi
