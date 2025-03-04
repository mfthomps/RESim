kill -9 $(ps aux | grep '[r]unTrack' | grep -v 'vi ' | awk '{print $2}')
