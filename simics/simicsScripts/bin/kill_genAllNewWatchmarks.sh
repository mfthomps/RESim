kill -9 $(ps aux | grep '[g]enAllNewWatchmarks.sh' | grep -v 'vi ' | awk '{print $2}')
