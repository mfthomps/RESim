kill -9 $(ps aux | grep '[r]unTrack' | awk '{print $2}')
