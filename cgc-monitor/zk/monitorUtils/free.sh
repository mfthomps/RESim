while [ 1 ]; do
   echo "`date`  free ram: `free | grep buffers/ | awk '{print $4}'`   used disk: `df -m | grep "/$" | awk '{print $5}'`"
   #echo "avail disk: `df -m | grep "/$" | awk '{print $5}'`"
   sleep 30
done

