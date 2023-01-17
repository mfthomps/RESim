if [ -z "$IDA_DIR" ]; then
    echo "IDA_DIR not defined."
    exit
fi
if [ $# -lt 2 ] || [ $1 = "-h" ]; then
    echo "syncIda.sh <target> <server>"
    exit
fi
target=$1
target_base="$(basename -- $target)"
remote=$2
remote_ida=$( ssh $remote "source $HOME/.resimrc;mkdir -p \$RESIM_IDA_DATA/$target_base; echo \$RESIM_IDA_DATA" )
if [ -z "$remote_ida" ];then
           echo "The $remote server needs a ~/.resimrc file containing the RESim env variables that may be in your ~/.bashrc file"
           exit 1
fi
rsync -avh $remote:$remote_ida/$target_base/*.hits $RESIM_IDA_DATA/$target_base/

