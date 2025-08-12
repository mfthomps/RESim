kill -9 $(ps aux | grep '[g]enNewWatchmarks.sh' | grep -v 'vi ' | awk '{print $2}')
