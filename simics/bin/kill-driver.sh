pkill background.sh
pkill drive-driver
kill -9 $(ps aux | grep '[d]rive-driver3.py' | awk '{print $2}') >>/dev/null 2>&1
