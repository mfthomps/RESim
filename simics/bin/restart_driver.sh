pkill driver-server.py
kill $(ps aux | grep '[d]river-server.py' | awk '{print $2}')
nohup /tmp/driver-server.py &
