#!/bin/bash
#
# Dump function/block IDA analysis for a given program.
# The output is placed in the analysis directory.  The IDA
# data base (idb, id0, etc.) is placed in the RESIM_IDA_DATA directory.
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
cp -u $RESIM_DIR/simics/ida/runRESim.idc $IDA_DIR/idc
if [[ $# -eq 0 ]] || [[ "$1" = "-h" ]]; then
    echo "idaDump.sh [-64] <program>"
    exit
fi
ida_suffix=id0
idacmd=$IDA_DIR/idat
if [[ "$1" == "-64" ]]; then
   echo "is 64"
   idacmd=$IDA_DIR/ida64t
   ida_suffix=i64
   shift 1
fi
target=$1
echo "target is $1"
target_base="$(basename -- "$target")"
echo "the target base is $target_base"
here="$(pwd)"
echo "we are currently: $here"
root_dir="$(basename --  "$here")"
echo "the root_dir is $root_dir"
old_dir=$RESIM_IDA_DATA/$target_base
new_dir=$RESIM_IDA_DATA/$root_dir/$target_base
if [[ -d $old_dir ]] && [[ ! -d $new_dir ]]; then
    echo "idaDump.sh assumes you are running from the file system root (per your ini file)."
    echo "If $old_dir is where the ida data is, rename it to $new_dir"
    echo "Or, if $old_dir is from some other system, fix its path, change its name, or remove it."
    exit
fi

target_path=$(realpath "$target")
ida_db_path=$RESIM_IDA_DATA/$root_dir/$target_base/$target_base.$ida_suffix

if [ -z "$IDA_ANALYSIS" ]; then
    export IDA_ANALYSIS=/mnt/resim_archive/analysis
fi
if [[ $target = $here/* ]]; then
    target=$(realpath --relative-to="${PWD}" "$target")
    echo "full path given to runIda, truncate it to $target"
fi

export ida_analysis_path=$IDA_ANALYSIS/$root_dir/$target
mkdir -p "$ida_analysis_path"

echo "target is $target"
echo "dbpath $ida_db_path"
if [[ -f $ida_db_path ]];then
    #$idacmd -S"$RESIM_DIR/simics/ida/RESimHotKey.idc $target_path $@" $ida_db_path
    #echo "ida_db_path is $ida_db_path"
    export IDA_DB_PATH=$ida_db_path
    echo $idacmd -L/tmp/idaDump.log -A -S$RESIM_DIR/simics/ida/idaDump.py $ida_db_path
    $idacmd -L/tmp/idaDump.log -A -S$RESIM_DIR/simics/ida/idaDump.py $ida_db_path
else
    echo "No IDA db at $ida_db_path  create it."
    mkdir -p "$RESIM_IDA_DATA/$root_dir/$target_base"
    #$idacmd -L/tmp/idaDump.log -A -o$ida_db_path -S$RESIM_DIR/simics/ida/idaDump.py "$target_path $@" "$target"
    $idacmd -L/tmp/idaDump.log -A -o$ida_db_path -S$RESIM_DIR/simics/ida/idaDump.py "$target"
fi
