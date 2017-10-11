uname=`uname`

result=$(uname -a | grep "64")
#echo "result is $result"
if [ ! -z "$result" ]; then
    uname="$uname"64
fi
echo $uname
