#
# Start IDA for a given target, setting a hotkey of "R" to attach to 
# the debugger and load the RESim IDA Client plugin. 
#
# The target file (to be disassembled) must be the first argument.
# Options for the 2nd argument include:
#     color -- reset IDA graph block colors and then color per the program hits files
#     reset -- just reset
#     remote -- remote host name for copying hits files.  TBD launch ssh tunnel if needed.
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
shift 1
if [ $# -gt 1 ];then
    echo "more than 1"
    remote=$2
    if [ $1 == color ]; then
       remote_ida=$( ssh $remote "echo \$RESIM_IDA_DATA" )
       rsync -avh $remote:$remote_ida/$target_base/*.hits $RESIM_IDA_DATA/$target_base/
    fi
fi

target_path=$(realpath $target)
ida_db_path=$RESIM_IDA_DATA/$target_base/$target_base.idb
echo "target is $target"
echo "dbpath $ida_db_path"
remain="$target_path $@"
if [[ -f $ida_db_path ]];then
    #$idacmd -S"$RESIM_DIR/simics/ida/RESimHotKey.idc $target_path $@" $ida_db_path
    $idacmd -S"$RESIM_DIR/simics/ida/RESimHotKey.idc $remain" $ida_db_path
else
    echo "No IDA db at $ida_db_path  create it."
    mkdir -p $RESIM_IDA_DATA/$target_base
    $idacmd -o$ida_db_path -S"$RESIM_DIR/simics/ida/RESimHotKey.idc $target_path $@" $target
fi
